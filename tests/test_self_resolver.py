"""Self-policy resolver (per-vantage, low-read) tests.

resolve_self reads the CURRENT principal's own policies (user or role) into a
normalized Grants and emits a self-node whose grant_statements feed correlation,
while empirically-probed permissions stay in a SEPARATE confirmed_actions
property (never fed into policy-derived correlation). It is NOT yet wired into
enumerate() - these exercise it directly.
"""

import json

import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402
import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from awspwn.aws_client import AwsClient  # noqa: E402
from awspwn.enum.base import EnumResult  # noqa: E402
from awspwn.enum.iam import IamEnumerator  # noqa: E402
from awspwn.models import AwsIdentity, NodeKind  # noqa: E402


ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def _client() -> AwsClient:
    c = AwsClient(AwsIdentity(access_key="testing", secret_key="testing", region="us-east-1", source="test"))
    c.whoami()
    return c


def _user_client(iam, username: str) -> AwsClient:
    """A client BOUND to `username` via its own access key, so get_user() /
    sts:GetCallerIdentity resolve to that user under moto (the realistic vantage)."""
    key = iam.create_access_key(UserName=username)["AccessKey"]
    c = AwsClient(AwsIdentity(access_key=key["AccessKeyId"], secret_key=key["SecretAccessKey"],
                              region="us-east-1", source="test"))
    c.whoami()
    return c


def _self_node(result):
    return next(n for n in result.nodes if n.properties.get("is_caller"))


# ─── user self-read ──────────────────────────────────────────────────────────


@mock_aws
def test_user_self_read_emits_structured_grants_and_separate_confirmed():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app"
    inline = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}]}
    iam.put_user_policy(UserName="dev", PolicyName="read", PolicyDocument=json.dumps(inline))

    client = _user_client(iam, "dev")
    result = IamEnumerator().resolve_self(client)
    node = _self_node(result)
    assert node.kind == NodeKind.IAM_USER
    # Policy-derived, structured, resource-aware.
    assert "grant_statements" in node.properties
    assert "secretsmanager:GetSecretValue" in node.properties["action_patterns"]
    # Empirically-confirmed probes are present and SEPARATE - never merged into
    # action_patterns (a successful probe proves only that one action).
    assert "confirmed_actions" in node.properties
    assert "sts:GetCallerIdentity" in node.properties["confirmed_actions"]
    assert "sts:GetCallerIdentity" not in node.properties["action_patterns"]
    assert node.properties.get("is_admin") is False


@mock_aws
def test_user_self_read_admin_mints_effective_admin():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="root-ish")
    iam.put_user_policy(UserName="root-ish", PolicyName="admin", PolicyDocument=json.dumps(ADMIN_DOC))

    client = _user_client(iam, "root-ish")
    result = IamEnumerator().resolve_self(client)

    node = _self_node(result)
    assert node.properties["is_admin"] is True
    assert any(n.properties.get("synthetic_goal") for n in result.nodes)  # admin goal minted
    assert any(e.kind == "EffectiveAdmin" and e.source_id == node.object_id for e in result.edges)


@mock_aws
def test_user_self_read_no_policies_is_authoritative_empty():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bare")
    client = _user_client(iam, "bare")
    node = _self_node(IamEnumerator().resolve_self(client))
    # Listings succeeded but returned nothing: present-and-empty (authoritative),
    # so a stale merged grant_statements would be superseded/cleared.
    assert node.properties["grant_statements"] == []
    assert node.properties["action_patterns"] == []
    assert node.properties["is_admin"] is False


# ─── role self-read (the primary post-pivot vantage) ─────────────────────────


@mock_aws
def test_role_self_read():
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(trust))
    inline = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/*"}]}
    iam.put_role_policy(RoleName="app", PolicyName="read", PolicyDocument=json.dumps(inline))

    client = _client()
    client.identity.arn = f"arn:aws:iam::{client.identity.account}:role/app"
    node = _self_node(IamEnumerator().resolve_self(client))
    assert node.kind == NodeKind.IAM_ROLE
    assert "s3:GetObject" in node.properties["action_patterns"]


# ─── denied reads OMIT grant_statements (do not assert unverified emptiness) ──


@mock_aws
def test_denied_self_read_omits_grants_but_keeps_confirmed(monkeypatch):
    boto3.client("iam", region_name="us-east-1").create_user(UserName="dev")
    client = _client()
    client.identity.arn = f"arn:aws:iam::{client.identity.account}:user/dev"

    iam = client.client("iam")  # cache + patch the exact object resolve_self reuses

    def denied(name):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, name)

    monkeypatch.setattr(iam, "get_paginator", denied)
    monkeypatch.setattr(iam, "get_user", lambda: denied("GetUser"))

    node = _self_node(IamEnumerator().resolve_self(client))
    # Could not read policies: DO NOT assert an empty grant set (a prior richer
    # vantage's data must survive the merge). Confirmed probes still recorded.
    assert "grant_statements" not in node.properties
    assert "grant_statements_partial" not in node.properties
    assert "action_patterns" not in node.properties
    assert "confirmed_actions" in node.properties


# ─── partial reads: non-authoritative, additive only ─────────────────────────


@mock_aws
def test_partial_user_read_when_group_listing_denied(monkeypatch):
    iam_admin = boto3.client("iam", region_name="us-east-1")
    iam_admin.create_user(UserName="dev")
    inline = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
    iam_admin.put_user_policy(UserName="dev", PolicyName="read", PolicyDocument=json.dumps(inline))
    client = _user_client(iam_admin, "dev")

    iam = client.client("iam")
    real_gp = iam.get_paginator

    def gp(name):
        if name == "list_groups_for_user":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, name)
        return real_gp(name)

    monkeypatch.setattr(iam, "get_paginator", gp)

    node = _self_node(IamEnumerator().resolve_self(client))
    # Coverage incomplete -> NON-authoritative: partial keys only, no authoritative
    # grant_statements/action_patterns/is_admin. Observed grants still recorded.
    assert node.properties["grant_read_status"] == "partial"
    assert "grant_statements" not in node.properties
    assert "action_patterns" not in node.properties
    assert "is_admin" not in node.properties
    assert "grant_statements_partial" in node.properties
    assert "s3:GetObject" in node.properties["action_patterns_partial"]


@mock_aws
def test_nested_document_denial_is_partial(monkeypatch):
    iam_admin = boto3.client("iam", region_name="us-east-1")
    iam_admin.create_user(UserName="dev")
    pol_arn = iam_admin.create_policy(
        PolicyName="Custom", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    )["Policy"]["Arn"]
    iam_admin.attach_user_policy(UserName="dev", PolicyArn=pol_arn)
    client = _user_client(iam_admin, "dev")

    iam = client.client("iam")

    def denied_version(**_kw):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetPolicyVersion")

    monkeypatch.setattr(iam, "get_policy_version", denied_version)

    node = _self_node(IamEnumerator().resolve_self(client))
    # A listing succeeded but a referenced DOCUMENT read failed -> partial.
    assert node.properties["grant_read_status"] == "partial"
    assert "grant_statements" not in node.properties
    assert "grant_statements_partial" in node.properties
    # The attached ARN is still known even though its document was unreadable.
    assert pol_arn in node.properties["attached_policies_partial"]


# ─── path-qualified role identity ────────────────────────────────────────────


@mock_aws
def test_path_qualified_role_uses_get_role_arn():
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="app", Path="/team/svc/", AssumeRolePolicyDocument=json.dumps(trust))

    client = _client()
    acct = client.identity.account
    # The vantage arrives path-STRIPPED (STS canonicalization drops the path).
    client.identity.arn = f"arn:aws:iam::{acct}:role/app"
    node = _self_node(IamEnumerator().resolve_self(client))
    # GetRole recovers the true path-qualified ARN for the node id.
    assert node.object_id == f"arn:aws:iam::{acct}:role/team/svc/app"


# ─── attached_policies preserved (incl. authoritative empty) ─────────────────


@mock_aws
def test_attached_policies_preserved_including_empty():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bare")
    node = _self_node(IamEnumerator().resolve_self(_user_client(iam, "bare")))
    assert node.properties["attached_policies"] == []   # authoritative empty


# ─── piecemeal (list-only) records are NOT authoritative ─────────────────────


@mock_aws
def test_enumerate_low_read_falls_back_to_self_resolve(monkeypatch):
    """Wiring: GAAD (and piecemeal) denied -> enumerate() self-resolves the current
    principal, yielding a complete self-node instead of a findings-only gap."""
    iam_admin = boto3.client("iam", region_name="us-east-1")
    iam_admin.create_user(UserName="dev")
    inline = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
    iam_admin.put_user_policy(UserName="dev", PolicyName="read", PolicyDocument=json.dumps(inline))
    client = _user_client(iam_admin, "dev")

    iam = client.client("iam")
    real_gp = iam.get_paginator
    denied = {"get_account_authorization_details", "list_users", "list_roles", "list_groups"}

    def gp(name):
        if name in denied:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, name)
        return real_gp(name)

    monkeypatch.setattr(iam, "get_paginator", gp)

    result = IamEnumerator().enumerate(client, "us-east-1")
    self_nodes = [n for n in result.nodes if n.properties.get("is_caller")]
    assert self_nodes, "no self-node produced on the low-read path"
    node = self_nodes[0]
    assert node.properties.get("grant_read_status") == "complete"
    assert "s3:GetObject" in node.properties["action_patterns"]
    assert "confirmed_actions" in node.properties


@mock_aws
def test_canonical_caller_path_qualifies_role():
    from awspwn.cli import _canonical_caller

    iam = boto3.client("iam", region_name="us-east-1")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="app", Path="/team/", AssumeRolePolicyDocument=json.dumps(trust))
    client = _client()
    acct = client.identity.account
    client.identity.arn = f"arn:aws:sts::{acct}:assumed-role/app/sess"  # session ARN (pathless)
    assert _canonical_caller(client) == f"arn:aws:iam::{acct}:role/team/app"


@mock_aws
def test_piecemeal_records_omit_authoritative_grants():
    client = _client()
    gaad = {
        "UserDetailList": [{"UserName": "dev", "Arn": "arn:aws:iam::111:user/dev",
                            "GroupList": [], "AttachedManagedPolicies": [], "UserPolicyList": []}],
        "GroupDetailList": [], "RoleDetailList": [], "Policies": [],
    }
    result = EnumResult()
    IamEnumerator()._build_from_gaad(gaad, "111", client, result, complete=False)
    dev = next(n for n in result.nodes if n.name == "dev")
    # List-only: must NOT publish ANY policy-derived property, or a later vantage
    # would downgrade a richer node / treat the principal as having no permissions.
    assert "grant_read_status" not in dev.properties
    assert "grant_statements" not in dev.properties
    assert "action_patterns" not in dev.properties
    assert "is_admin" not in dev.properties
