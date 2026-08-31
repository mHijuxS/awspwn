"""roam interactive pivot-loop tests.

Exercise the loop invariants: one hop per menu turn, plan-mode previews without
pivoting, an identity-changing hop triggers exactly one recollection, and only
q / EOF ends the loop (reaching admin does not).
"""

import argparse
import json
import os

import pytest

# Self-escalation strategies attach AdministratorAccess by ARN; ask moto to load
# the managed-policy set so those paths run.
os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")

from awspwn.cli import _roam_hops, cmd_roam  # noqa: E402
from awspwn.graph import AttackGraph  # noqa: E402
from awspwn.models import Edge, Node, NodeKind  # noqa: E402

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402
import boto3  # noqa: E402

from awspwn.aws_client import AwsClient  # noqa: E402
from awspwn.enum.base import run_all  # noqa: E402
from awspwn.enum.correlate import reconcile_resource_edges  # noqa: E402
from awspwn.enum.iam import IamEnumerator  # noqa: E402
from awspwn.enum.sts import StsEnumerator  # noqa: E402
from awspwn.models import AwsIdentity  # noqa: E402
from awspwn.state import State, save_graph, save_state  # noqa: E402


# ─── _roam_hops: actionable, sorted, structural excluded ─────────────────────


def test_roam_hops_excludes_structural_and_ranks_identity_first():
    nodes = {
        "u": Node("u", "dev", NodeKind.IAM_USER),
        "r": Node("r", "role", NodeKind.IAM_ROLE),
        "g": Node("g", "grp", NodeKind.IAM_GROUP),
        "s": Node("s", "sec", NodeKind.SECRET),
    }
    edges = [
        Edge("u", "g", "MemberOf"),          # structural -> excluded
        Edge("u", "s", "GetSecretValue"),    # resource read
        Edge("u", "r", "CanAssume"),         # identity change
    ]
    hops = _roam_hops(AttackGraph(nodes, edges), "u")
    kinds = [e.kind for e, _d, _i in hops]
    assert "MemberOf" not in kinds
    assert kinds[0] == "CanAssume"           # identity-changing ranked first
    assert set(kinds) == {"CanAssume", "GetSecretValue"}


# ─── loop mechanics (moto) ───────────────────────────────────────────────────

ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def _seed_and_build(tmp_path):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    key = iam.create_access_key(UserName="dev")["AccessKey"]
    account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    admin_pol = iam.create_policy(PolicyName="CustomAdmin", PolicyDocument=json.dumps(ADMIN_DOC))["Policy"]["Arn"]
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:user/dev"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="admin-role", AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName="admin-role", PolicyArn=admin_pol)

    dev = AwsClient(AwsIdentity(access_key=key["AccessKeyId"], secret_key=key["SecretAccessKey"],
                                region="us-east-1", source="test"))
    dev.whoami()

    result = run_all(dev, [StsEnumerator(), IamEnumerator()], regions=["us-east-1"])
    ups, _rem = reconcile_resource_edges(result.nodes, result.edges)
    result.edges.extend(ups)
    state = State(origin_account=account, caller_arn=dev.identity.arn)
    for n in result.nodes:
        state.add_node(n)
    for e in result.edges:
        state.add_edge(e)
    save_state(state, str(tmp_path))
    save_graph(state, str(tmp_path))
    return dev, account


def _args(tmp_path, dev, **over):
    a = argparse.Namespace(
        profile="", region="us-east-1", access_key="", secret_key="", session_token="",
        loot_dir=str(tmp_path), data=None, no_cache=False, max_depth=12, no_color=True,
        verbose=False, source=None, execute=False, allow_destructive=False, allow_external=False,
        allow_orphan=False, iam_only=True, session_name="awspwn", command="roam", _live_client=dev,
    )
    for k, v in over.items():
        setattr(a, k, v)
    return a


def _feed(monkeypatch, seq):
    it = iter(seq)
    monkeypatch.setattr("builtins.input", lambda *a: next(it))


def _key_client(iam, username):
    key = iam.create_access_key(UserName=username)["AccessKey"]
    c = AwsClient(AwsIdentity(access_key=key["AccessKeyId"], secret_key=key["SecretAccessKey"],
                              region="us-east-1", source="test"))
    c.whoami()
    return c


def _persist(client, account, tmp_path):
    """Enumerate `client`'s vantage and save graph.json/state.json to tmp_path."""
    result = run_all(client, [StsEnumerator(), IamEnumerator()], regions=["us-east-1"])
    ups, _rem = reconcile_resource_edges(result.nodes, result.edges)
    result.edges.extend(ups)
    state = State(origin_account=account, caller_arn=client.identity.arn)
    for n in result.nodes:
        state.add_node(n)
    for e in result.edges:
        state.add_edge(e)
    save_state(state, str(tmp_path))
    save_graph(state, str(tmp_path))


# ─── cross-account context (unit) ────────────────────────────────────────────


def test_engine_context_prefers_live_identity_account():
    from awspwn.state import State as _State
    from awspwn.strategy import Gates, PwnEngine

    eng = PwnEngine(_State(), AttackGraph({}, []), Gates(), account="111111111111")
    client = AwsClient(AwsIdentity(arn="arn:aws:iam::222222222222:role/x", account="222222222222"))
    src = Node("s", "s", NodeKind.IAM_ROLE)
    dst = Node("d", "d", NodeKind.IAM_ROLE)
    # After a cross-account pivot, templates must target the LIVE account.
    assert eng.context(client, src, dst)["ACCOUNT_ID"] == "222222222222"


@mock_aws
def test_roam_plan_mode_previews_without_pivot(tmp_path, monkeypatch, capsys):
    dev, _acct = _seed_and_build(tmp_path)
    _feed(monkeypatch, ["1", "q"])
    rc = cmd_roam(_args(tmp_path, dev, execute=False))
    out = capsys.readouterr().out
    assert rc == 0
    assert "plan mode" in out
    assert "no pivot" in out
    assert "now:" not in out            # never claims a pivot occurred
    assert "re-collecting" not in out


@mock_aws
def test_roam_executes_one_hop_pivots_and_recollects(tmp_path, monkeypatch, capsys):
    dev, account = _seed_and_build(tmp_path)
    # Hop 1 is CanAssume -> admin-role (identity-changing, high-value), then quit.
    _feed(monkeypatch, ["1", "q"])
    rc = cmd_roam(_args(tmp_path, dev, execute=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "now:" in out                              # identity changed
    assert "assumed-role/awspwn" in out or "role/admin-role" in out
    assert "re-collecting from the new vantage" in out  # recollected after pivot
    assert "roam ended" in out                        # clean termination on q


@mock_aws
def test_roam_quits_immediately_on_q(tmp_path, monkeypatch, capsys):
    dev, _acct = _seed_and_build(tmp_path)
    _feed(monkeypatch, ["q"])
    rc = cmd_roam(_args(tmp_path, dev, execute=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "roam ended" in out
    assert "0 hop(s)" in out


# ─── gap 1: cached graph -> collect the initial vantage ──────────────────────


@mock_aws
def test_roam_execute_collects_initial_vantage_from_cache(tmp_path, monkeypatch, capsys):
    dev, _acct = _seed_and_build(tmp_path)   # graph is now on disk (a cache)
    _feed(monkeypatch, ["q"])
    # _collected is NOT set -> roam must collect vantage 1 before roaming.
    cmd_roam(_args(tmp_path, dev, execute=True))
    out = capsys.readouterr().out
    assert "collecting the initial vantage" in out
    assert "collected from" in out


# ─── gap 2: refuse execute when source != caller ─────────────────────────────


@mock_aws
def test_roam_refuses_execute_from_mismatched_source(tmp_path, monkeypatch, capsys):
    dev, _acct = _seed_and_build(tmp_path)
    _feed(monkeypatch, ["q"])
    rc = cmd_roam(_args(tmp_path, dev, execute=True, source="admin-role"))
    out = capsys.readouterr().out
    assert rc == 1
    assert "refusing to execute" in out


# ─── gap 3: same-principal replacement creds -> no recollection ───────────────


@mock_aws
def test_roam_same_principal_replacement_creds_no_recollect(tmp_path, monkeypatch, capsys):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    # A secret dev can read; it contains a SECOND valid dev key (same principal).
    second = iam.create_access_key(UserName="dev")["AccessKey"]
    sec = sm.create_secret(Name="devcreds", SecretString=json.dumps({
        "aws_access_key_id": second["AccessKeyId"],
        "aws_secret_access_key": second["SecretAccessKey"]}))["ARN"]
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": sec}]}
    iam.put_user_policy(UserName="dev", PolicyName="read", PolicyDocument=json.dumps(policy))

    dev = _key_client(iam, "dev")
    _persist(dev, account, tmp_path)
    _feed(monkeypatch, ["1", "q"])
    # iam_only=False so the initial-vantage collection enumerates the secret (and
    # its GetSecretValue edge); region stays us-east-1, so it's a 1-region sweep.
    cmd_roam(_args(tmp_path, dev, execute=True, iam_only=False))
    out = capsys.readouterr().out
    assert "replacement credentials for the same principal" in out
    assert "re-collecting from the new vantage" not in out


# ─── manual r: re-recon the current vantage ──────────────────────────────────


@mock_aws
def test_roam_r_recollects_current_vantage(tmp_path, monkeypatch, capsys):
    dev, _acct = _seed_and_build(tmp_path)
    _feed(monkeypatch, ["r", "q"])
    cmd_roam(_args(tmp_path, dev, execute=True))
    out = capsys.readouterr().out
    assert "re-collecting the current vantage" in out


# ─── safety: a completed mutating hop is not offered again ───────────────────


@mock_aws
def test_roam_completed_mutation_hop_not_repeatable(tmp_path, monkeypatch, capsys):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    escalate = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}]}
    iam.put_user_policy(UserName="dev", PolicyName="esc", PolicyDocument=json.dumps(escalate))

    dev = _key_client(iam, "dev")
    _persist(dev, account, tmp_path)
    # Hop 1 is AttachUserPolicy -> admin goal (MUTATE, same identity). Then the
    # menu should show it [done] rather than offering it again.
    _feed(monkeypatch, ["1", "q"])
    cmd_roam(_args(tmp_path, dev, execute=True))
    out = capsys.readouterr().out
    assert "REACHED" in out
    assert "[done]" in out
    assert "1 hop(s)" in out
