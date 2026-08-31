"""moto-backed phase-3 exploitation tests.

Exercise the PwnEngine's per-edge strategies against a mock account and assert:
  * credential propagation (a strategy yields a usable next-hop identity);
  * the mutation ledger records a concrete undo for every mutating call;
  * rollback replays it LIFO, is idempotent, and restores overwrite-style state;
  * blast-radius gates block DESTRUCTIVE/EXTERNAL and plan mode mutates nothing;
  * embedded credentials are pulled out of a secret and propagated.

moto note: the Lambda-as-role and SSM-SendCommand strategies need real runtime
execution (docker / a live instance) and are NOT covered here - they are tested
against the runbook renderer and left to live engagements.
"""

import json
import os

# moto does not preload the AWS-managed policies (e.g. AdministratorAccess) by
# default; the self-escalation strategies attach it by ARN, which is valid on
# real AWS. Ask moto to load the managed-policy set so those paths are testable.
os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")

import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

import boto3  # noqa: E402

from awspwn.aws_client import AwsClient  # noqa: E402
from awspwn.graph import AttackGraph  # noqa: E402
from awspwn.models import (  # noqa: E402
    AttackPath,
    AwsIdentity,
    Edge,
    Node,
    NodeKind,
)
from awspwn.rollback import rollback  # noqa: E402
from awspwn.state import State, load_state  # noqa: E402
from awspwn.strategy import Gates, PwnEngine, render_plan  # noqa: E402

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _account():
    return boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]


def _client_as(arn: str, account: str) -> AwsClient:
    """A client whose boto3 calls hit moto (any creds work) but whose *identity*
    is pinned to `arn`, so self-escalation strategies target the right principal
    deterministically regardless of moto's STS key resolution."""
    c = AwsClient(AwsIdentity(access_key="testing", secret_key="testing", region="us-east-1", source="test"))
    c.identity.arn = arn
    c.identity.account = account
    return c


def _admin_goal(account: str) -> Node:
    return Node(object_id=f"awspwn:admin:{account}", name="admin", kind=NodeKind.AWS_ACCOUNT,
                account=account, properties={"synthetic_goal": True, "is_admin": True})


def _engine(tmp_path, path: AttackPath, gates: Gates, account: str) -> PwnEngine:
    graph = AttackGraph({n.object_id: n for n in path.nodes}, list(path.edges))
    state = State(origin_account=account, caller_arn=path.nodes[0].object_id)
    return PwnEngine(state, graph, gates, account=account, region="us-east-1",
                     loot_dir=str(tmp_path), log=lambda _m: None)


def _one_hop(src: Node, kind: str, dst: Node, **props) -> AttackPath:
    return AttackPath(nodes=[src, dst], edges=[Edge(src.object_id, dst.object_id, kind, props)])


# ─── Self-escalation + rollback ─────────────────────────────────────────────


@mock_aws
def test_attach_user_policy_self_admin_and_rollback(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    goal = _admin_goal(account)
    path = _one_hop(dev, "AttachUserPolicy", goal)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    client = _client_as(dev.object_id, account)
    report = engine.walk(path, client)

    assert report.reached_goal
    attached = [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName="dev")["AttachedPolicies"]]
    assert ADMIN_ARN in attached, "admin not attached to dev"
    assert engine.mutation_count == 1
    m = engine.state.mutations[0]
    assert m.api == "iam:AttachUserPolicy" and m.undo_api == "iam:DetachUserPolicy"
    assert not m.reverted

    # Persisted to the ledger on disk.
    reloaded = load_state(str(tmp_path))
    assert len(reloaded.mutations) == 1

    rep = rollback(engine.state, client, str(tmp_path), log=lambda _m: None)
    assert rep.ok and len(rep.reverted) == 1
    attached_after = iam.list_attached_user_policies(UserName="dev")["AttachedPolicies"]
    assert not attached_after, "rollback did not detach admin"


@mock_aws
def test_create_access_key_records_undo_and_propagates(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    iam.create_user(UserName="ops")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    ops = Node(object_id=f"arn:aws:iam::{account}:user/ops", name="ops", kind=NodeKind.IAM_USER, account=account)
    path = _one_hop(dev, "CreateAccessKey", ops)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    report = engine.walk(path, _client_as(dev.object_id, account))

    # A real key now exists on ops, and the ledger can delete it.
    keys = iam.list_access_keys(UserName="ops")["AccessKeyMetadata"]
    assert len(keys) == 1
    m = engine.state.mutations[0]
    assert m.api == "iam:CreateAccessKey" and m.undo_api == "iam:DeleteAccessKey"
    assert m.undo_params["AccessKeyId"] == keys[0]["AccessKeyId"]
    # Credential propagation: the walk minted a usable ops session.
    assert report.final_arn  # changed to the new identity

    rollback(engine.state, _client_as(dev.object_id, account), str(tmp_path), log=lambda _m: None)
    assert not iam.list_access_keys(UserName="ops")["AccessKeyMetadata"], "key not deleted on rollback"


@mock_aws
def test_create_access_key_persists_and_reuses(tmp_path):
    from awspwn.state import load_captured_creds

    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    iam.create_user(UserName="ops")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    ops = Node(object_id=f"arn:aws:iam::{account}:user/ops", name="ops", kind=NodeKind.IAM_USER, account=account)
    path = _one_hop(dev, "CreateAccessKey", ops)

    # First walk: mints the key AND persists it to the 0600 loot store.
    e1 = _engine(tmp_path, path, Gates(execute=True), account)
    r1 = e1.walk(path, _client_as(dev.object_id, account))
    assert len(iam.list_access_keys(UserName="ops")["AccessKeyMetadata"]) == 1
    assert r1.captured, "created key not surfaced to the operator"
    stored = load_captured_creds(str(tmp_path))
    assert any(c["target_arn"] == ops.object_id and c["access_key"] and c["secret_key"] for c in stored)
    import os
    import stat as statmod
    store_file = tmp_path / "captured-creds.jsonl"
    assert statmod.S_IMODE(os.stat(store_file).st_mode) == 0o600, "cred store not 0600"

    # Second walk, same loot dir: reuses the stored key, mints NO second key.
    e2 = _engine(tmp_path, path, Gates(execute=True), account)
    r2 = e2.walk(path, _client_as(dev.object_id, account))
    assert len(iam.list_access_keys(UserName="ops")["AccessKeyMetadata"]) == 1, "reuse minted a duplicate key"
    assert e2.mutation_count == 0, "reuse recorded a mutation"
    assert r2.captured


@mock_aws
def test_add_user_to_group_and_rollback(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    iam.create_group(GroupName="admins")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    grp = Node(object_id=f"arn:aws:iam::{account}:group/admins", name="admins", kind=NodeKind.IAM_GROUP, account=account)
    path = _one_hop(dev, "AddUserToGroup", grp)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    engine.walk(path, _client_as(dev.object_id, account))

    groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName="dev")["Groups"]]
    assert "admins" in groups
    rollback(engine.state, _client_as(dev.object_id, account), str(tmp_path), log=lambda _m: None)
    assert "admins" not in [g["GroupName"] for g in iam.list_groups_for_user(UserName="dev")["Groups"]]


@mock_aws
def test_update_assume_role_policy_captures_original_and_restores(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    original_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName="target", AssumeRolePolicyDocument=json.dumps(original_trust))
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    role = Node(object_id=f"arn:aws:iam::{account}:role/target", name="target", kind=NodeKind.IAM_ROLE, account=account)
    path = _one_hop(dev, "UpdateAssumeRolePolicy", role)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    engine.walk(path, _client_as(dev.object_id, account))

    m = engine.state.mutations[0]
    assert m.original_state and "AssumeRolePolicyDocument" in m.original_state
    # Trust now allows dev.
    live = iam.get_role(RoleName="target")["Role"]["AssumeRolePolicyDocument"]
    assert "dev" in json.dumps(live)

    rollback(engine.state, _client_as(dev.object_id, account), str(tmp_path), log=lambda _m: None)
    restored = iam.get_role(RoleName="target")["Role"]["AssumeRolePolicyDocument"]
    assert restored == original_trust, "trust policy not restored to the captured original"


@mock_aws
def test_create_role_and_assume_rolls_back_lifo(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    goal = _admin_goal(account)
    path = _one_hop(dev, "CreateRoleAndAssume", goal)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    report = engine.walk(path, _client_as(dev.object_id, account))
    assert report.reached_goal
    assert iam.get_role(RoleName="awspwn-role")  # created

    # Two mutations: CreateRole then AttachRolePolicy. Rollback must detach first.
    assert [m.api for m in engine.state.mutations] == ["iam:CreateRole", "iam:AttachRolePolicy"]
    rep = rollback(engine.state, _client_as(dev.object_id, account), str(tmp_path), log=lambda _m: None)
    assert rep.ok
    with pytest.raises(iam.exceptions.NoSuchEntityException):
        iam.get_role(RoleName="awspwn-role")

    # Idempotent: a second rollback is a no-op.
    rep2 = rollback(engine.state, _client_as(dev.object_id, account), str(tmp_path), log=lambda _m: None)
    assert rep2.ok and not rep2.reverted


@mock_aws
def test_guarded_mutation_drops_phantom_on_clean_failure(tmp_path):
    account = _account()
    # The identity claims to be 'ghost', but no such IAM user exists, so
    # attach_user_policy raises NoSuchEntity: the recorded mutation must be
    # rolled off the ledger (record-before-call + drop-on-clean-failure).
    ghost = Node(object_id=f"arn:aws:iam::{account}:user/ghost", name="ghost", kind=NodeKind.IAM_USER, account=account)
    goal = _admin_goal(account)
    path = _one_hop(ghost, "AttachUserPolicy", goal)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    report = engine.walk(path, _client_as(ghost.object_id, account))
    assert not report.reached_goal
    assert engine.mutation_count == 0
    assert len(engine.state.mutations) == 0, "phantom mutation left on ledger after a failed call"
    # And the persisted ledger is clean too.
    assert not load_state(str(tmp_path)).mutations


@mock_aws
def test_create_policy_version_rollback_fully_cleans_up(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    benign = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    pol_arn = iam.create_policy(PolicyName="app", PolicyDocument=json.dumps(benign))["Policy"]["Arn"]
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER,
               account=account, properties={"attached_policies": [pol_arn]})
    goal = _admin_goal(account)
    path = _one_hop(dev, "CreatePolicyVersion", goal)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    report = engine.walk(path, _client_as(dev.object_id, account))
    assert report.reached_goal
    # Two ledger entries: create-version and set-default.
    assert [m.api for m in engine.state.mutations] == ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
    versions = iam.list_policy_versions(PolicyArn=pol_arn)["Versions"]
    assert len(versions) == 2

    rep = rollback(engine.state, _client_as(dev.object_id, account), str(tmp_path), log=lambda _m: None)
    assert rep.ok
    versions_after = iam.list_policy_versions(PolicyArn=pol_arn)["Versions"]
    assert len(versions_after) == 1, "created policy version not deleted on rollback"
    assert versions_after[0]["IsDefaultVersion"], "prior default not restored"


@mock_aws
def test_engine_retains_final_elevated_client(tmp_path):
    # After propagating identity, the engine keeps the furthest client so
    # `pwn --cleanup` can undo artifacts as the gained (privileged) identity.
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:user/dev"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName="target", AssumeRolePolicyDocument=json.dumps(trust))
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    role = Node(object_id=f"arn:aws:iam::{account}:role/target", name="target", kind=NodeKind.IAM_ROLE, account=account)
    path = _one_hop(dev, "CanAssume", role)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    engine.walk(path, _client_as(dev.object_id, account))
    assert engine.final_client is not None
    assert "assumed-role/target" in engine.final_client.identity.arn


# ─── Gates ──────────────────────────────────────────────────────────────────


@mock_aws
def test_gate_blocks_destructive_without_flag(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="victim")
    iam.create_login_profile(UserName="victim", Password="Original-Pw1!")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    victim = Node(object_id=f"arn:aws:iam::{account}:user/victim", name="victim", kind=NodeKind.IAM_USER, account=account)
    # UpdateLoginProfile is DESTRUCTIVE.
    path = _one_hop(dev, "UpdateLoginProfile", victim)

    engine = _engine(tmp_path, path, Gates(execute=True, allow_destructive=False), account)
    report = engine.walk(path, _client_as(dev.object_id, account))
    assert not report.reached_goal
    assert engine.mutation_count == 0, "a DESTRUCTIVE step ran without --allow-destructive"
    assert report.blocked


@mock_aws
def test_plan_mode_mutates_nothing(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    goal = _admin_goal(account)
    path = _one_hop(dev, "AttachUserPolicy", goal)

    engine = _engine(tmp_path, path, Gates(execute=False), account)  # plan mode
    report = engine.walk(path, _client_as(dev.object_id, account))
    assert engine.mutation_count == 0
    assert not iam.list_attached_user_policies(UserName="dev")["AttachedPolicies"]
    assert report.blocked

    # render_plan flags the blocked hop.
    plan = render_plan(path, Gates(execute=False))
    assert "BLOCKED" in plan


# ─── Data-edge credential capture ───────────────────────────────────────────


@mock_aws
def test_get_secret_captures_embedded_creds(tmp_path):
    account = _account()
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    embedded = {"aws_access_key_id": "AKIAEMBEDDED1234567X", "aws_secret_access_key": "s" * 40}
    arn = sm.create_secret(Name="db-creds", SecretString=json.dumps(embedded))["ARN"]
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    secret = Node(object_id=arn, name="db-creds", kind=NodeKind.SECRET, account=account)
    path = _one_hop(dev, "GetSecretValue", secret)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    report = engine.walk(path, _client_as(dev.object_id, account))
    assert report.captured, "no credentials captured from the secret"
    assert report.captured[0].access_key == "AKIAEMBEDDED1234567X"
    # A read edge mutates nothing.
    assert engine.mutation_count == 0


@mock_aws
def test_unverified_embedded_creds_not_propagated(tmp_path, monkeypatch):
    account = _account()
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    embedded = {"aws_access_key_id": "AKIAROTATED000000000", "aws_secret_access_key": "z" * 40}
    arn = sm.create_secret(Name="rotated", SecretString=json.dumps(embedded))["ARN"]
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    secret = Node(object_id=arn, name="rotated", kind=NodeKind.SECRET, account=account)
    path = _one_hop(dev, "GetSecretValue", secret)

    # Simulate the embedded creds failing to authenticate (rotated/false positive).
    import awspwn.strategy as strat
    monkeypatch.setattr(strat, "_verified_client", lambda creds, ctx, source: None)

    engine = _engine(tmp_path, path, Gates(execute=True), account)
    report = engine.walk(path, _client_as(dev.object_id, account))
    assert not report.captured, "unusable creds were reported as captured"
    assert report.final_arn == dev.object_id, "working identity was replaced by a dead client"
    assert any("unverified" in item for item in report.loot)


def test_choose_path_refuses_in_non_tty():
    import argparse
    from awspwn.cli import _choose_path

    dev = Node(object_id="arn:aws:iam::111111111111:user/dev", name="dev", kind=NodeKind.IAM_USER)
    goal = _admin_goal("111111111111")
    p1 = AttackPath(nodes=[dev, goal], edges=[Edge(dev.object_id, goal.object_id, "AttachUserPolicy", {})])
    p2 = AttackPath(nodes=[dev, goal], edges=[Edge(dev.object_id, goal.object_id, "PutUserPolicy", {})])
    # pytest runs with a non-TTY stdin; multiple paths and no -y must NOT auto-run.
    choice, code = _choose_path([p1, p2], argparse.Namespace(yes=False), dev)
    assert choice is None and code == 2


def test_rollback_dry_run_needs_no_client(tmp_path):
    from awspwn.models import Mutation

    st = State(origin_account="111111111111")
    st.mutations.append(Mutation(
        ts="t", api="iam:AttachUserPolicy", params={}, principal_used="p", blast_radius="MUTATE",
        undo_api="iam:DetachUserPolicy", undo_params={"UserName": "dev", "PolicyArn": "x"},
    ))
    rep = rollback(st, None, str(tmp_path), log=lambda _m: None, dry_run=True)  # client=None
    assert rep.ok and not rep.reverted
    assert not st.mutations[0].reverted, "dry-run must not mutate the ledger"


# ─── Fallback chain ─────────────────────────────────────────────────────────


@mock_aws
def test_fallback_tries_sibling_edge(tmp_path):
    account = _account()
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    dev = Node(object_id=f"arn:aws:iam::{account}:user/dev", name="dev", kind=NodeKind.IAM_USER, account=account)
    goal = _admin_goal(account)
    # Two ways to admin: a DESTRUCTIVE-gated route (blocked) and a plain MUTATE route.
    nodes = [dev, goal]
    edges = [
        Edge(dev.object_id, goal.object_id, "UpdateLoginProfile", {}),  # not even a self-admin path; will fail
        Edge(dev.object_id, goal.object_id, "AttachUserPolicy", {}),    # the working fallback
    ]
    path = AttackPath(nodes=nodes, edges=[edges[0]])
    graph = AttackGraph({n.object_id: n for n in nodes}, edges)
    state = State(origin_account=account, caller_arn=dev.object_id)
    engine = PwnEngine(state, graph, Gates(execute=True, allow_destructive=True), account=account,
                       region="us-east-1", loot_dir=str(tmp_path), log=lambda _m: None)
    report = engine.walk(path, _client_as(dev.object_id, account))
    # The first edge cannot self-escalate (UpdateLoginProfile targets the admin
    # goal node, which is not a user); fallback should reach admin via AttachUserPolicy.
    assert ADMIN_ARN in [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName="dev")["AttachedPolicies"]]
    assert report.reached_goal
