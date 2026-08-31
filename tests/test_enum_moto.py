"""moto-backed enumeration tests.

Seed a known-vulnerable IAM layout, run the real enumerators against the mock,
and assert the graph + pathfinding surface the escalation. Also assert the
read-only phases never mutate account state.
"""

import json

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from awspwn.aws_client import AwsClient  # noqa: E402
from awspwn.enum.base import run_all  # noqa: E402
from awspwn.enum.correlate import correlate_resource_edges  # noqa: E402
from awspwn.enum.iam import IamEnumerator  # noqa: E402
from awspwn.enum.sts import StsEnumerator  # noqa: E402
from awspwn.graph import AttackGraph  # noqa: E402
from awspwn.models import AwsIdentity  # noqa: E402


ADMIN_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
ATTACH_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}],
}


def _seed():
    """A user 'dev' who can iam:AttachUserPolicy (self-escalate to admin),
    plus an 'admin-role' that trusts 'dev' and holds a customer-managed admin
    policy. (A customer-managed policy is used rather than the AWS-managed
    AdministratorAccess so the test does not depend on moto pre-loading it, and
    so the offline matcher's document-based is_admin detection is exercised.)"""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    iam.put_user_policy(UserName="dev", PolicyName="escalate", PolicyDocument=json.dumps(ATTACH_DOC))

    account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    admin_pol = iam.create_policy(
        PolicyName="CustomAdmin", PolicyDocument=json.dumps(ADMIN_DOC)
    )["Policy"]["Arn"]

    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:user/dev"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName="admin-role", AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName="admin-role", PolicyArn=admin_pol)
    return account


def _client() -> AwsClient:
    ident = AwsIdentity(
        access_key="testing",
        secret_key="testing",
        region="us-east-1",
        source="test",
    )
    c = AwsClient(ident)
    c.whoami()
    return c


@mock_aws
def test_enum_builds_graph_and_finds_path():
    _seed()
    client = _client()
    result = run_all(client, [StsEnumerator(), IamEnumerator()], regions=["us-east-1"])
    result.edges.extend(correlate_resource_edges(result.nodes, result.edges))

    nodes = {n.object_id: n for n in result.nodes}
    graph = AttackGraph(nodes, result.edges)

    dev = graph.get_node("dev")
    assert dev is not None, "dev user not enumerated"

    admin_role = graph.get_node("admin-role")
    assert admin_role is not None
    assert admin_role.properties.get("is_admin"), "admin-role not flagged admin"

    # CanAssume edge dev -> admin-role from the trust policy.
    kinds = {e.kind for e in graph.outgoing_edges(dev.object_id)}
    assert "CanAssume" in kinds, f"no CanAssume edge, got {kinds}"

    # Self-escalation edge dev -> admin goal from iam:AttachUserPolicy.
    goal = next(n for n in result.nodes if n.properties.get("synthetic_goal"))
    path = graph.find_shortest_path(dev.object_id, goal.object_id)
    assert path is not None, "no path from dev to admin"


@mock_aws
def test_degradation_records_denied(monkeypatch):
    _seed()
    client = _client()

    # Force GAAD + list_users/roles/groups to fail, exercising the brute-force leg.
    real_client = client.client

    def gimped(service, region=None):
        c = real_client(service, region)
        if service == "iam":
            def deny(*a, **k):
                from botocore.exceptions import ClientError
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "op")
            c.get_paginator = lambda *a, **k: (_ for _ in ()).throw(
                __import__("botocore.exceptions", fromlist=["ClientError"]).ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetAccountAuthorizationDetails"
                )
            )
        return c

    monkeypatch.setattr(client, "client", gimped)
    result = run_all(client, [IamEnumerator()], regions=["us-east-1"])
    # Brute-force leg should have produced at least one finding about denial.
    assert any("brute-force" in f.title.lower() or "AccessDenied" in f.title for f in result.findings)


@mock_aws
def test_readonly_enum_does_not_mutate():
    _seed()
    iam = boto3.client("iam", region_name="us-east-1")

    def snapshot():
        users = iam.list_users()["Users"]
        roles = iam.list_roles()["Roles"]
        return (
            sorted(u["UserName"] for u in users),
            sorted(r["RoleName"] for r in roles),
        )

    before = snapshot()
    client = _client()
    run_all(client, [StsEnumerator(), IamEnumerator()], regions=["us-east-1"])
    after = snapshot()
    assert before == after, "read-only enumeration mutated IAM state"
