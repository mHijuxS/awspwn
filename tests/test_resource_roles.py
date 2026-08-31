"""Resource-derived role nodes + precise structural edges (Step 6, sub-step 1).

Referenced execution/task/instance-profile roles become real IAM_ROLE nodes with
accurate, non-abusable structural edges. Instance-profile roles are resolved via
GetInstanceProfile (never inferred from the profile name), and these structural
references are not traversable pivots (absent from _roam_hops).
"""

import io
import zipfile

import pytest

from awspwn.cli import _roam_hops
from awspwn.graph import AttackGraph
from awspwn.models import Edge, Node, NodeKind

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402
import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from awspwn.aws_client import AwsClient  # noqa: E402
from awspwn.enum.compute_extra import ComputeExtraEnumerator  # noqa: E402
from awspwn.enum.ec2 import Ec2Enumerator  # noqa: E402
from awspwn.enum.lambda_fn import LambdaEnumerator  # noqa: E402
from awspwn.models import AwsIdentity  # noqa: E402

TRUST = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"x.amazonaws.com"},"Action":"sts:AssumeRole"}]}'


def _client():
    c = AwsClient(AwsIdentity(access_key="testing", secret_key="testing", region="us-east-1", source="test"))
    c.whoami()
    return c


def _edge_map(result):
    return {(e.source_id, e.target_id, e.kind) for e in result.edges}


def _nodes_of(result, kind):
    return [n for n in result.nodes if n.kind == kind]


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(e, c):\n    return 1\n")
    return buf.getvalue()


# ─── Lambda execution role ───────────────────────────────────────────────────


@mock_aws
def test_lambda_execution_role_becomes_node_with_structural_edge():
    iam = boto3.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(RoleName="lambda-exec", AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    lam = boto3.client("lambda", region_name="us-east-1")
    fn = lam.create_function(FunctionName="fn", Runtime="python3.12", Role=role_arn,
                             Handler="index.handler", Code={"ZipFile": _zip()})["FunctionArn"]

    result = LambdaEnumerator().enumerate(_client(), "us-east-1")
    assert role_arn in {n.object_id for n in _nodes_of(result, NodeKind.IAM_ROLE)}
    assert (fn, role_arn, "LambdaExecutionRole") in _edge_map(result)


# ─── ECS task role (workload) vs execution role (structural only) ────────────


@mock_aws
def test_ecs_task_role_is_workload_execution_role_is_structural():
    iam = boto3.client("iam", region_name="us-east-1")
    task_role = iam.create_role(RoleName="task", AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    exec_role = iam.create_role(RoleName="exec", AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    ecs = boto3.client("ecs", region_name="us-east-1")
    td = ecs.register_task_definition(
        family="app", taskRoleArn=task_role, executionRoleArn=exec_role,
        containerDefinitions=[{"name": "c", "image": "img", "memory": 128}],
    )["taskDefinition"]["taskDefinitionArn"]

    result = ComputeExtraEnumerator().enumerate(_client(), "us-east-1")
    edges = _edge_map(result)
    assert (td, task_role, "ECSTaskRole") in edges         # workload identity
    assert (td, exec_role, "ECSExecutionRole") in edges    # structural metadata only
    role_ids = {n.object_id for n in _nodes_of(result, NodeKind.IAM_ROLE)}
    assert {task_role, exec_role} <= role_ids
    # The execution role is never emitted as a task (workload) role.
    assert (td, exec_role, "ECSTaskRole") not in edges


# ─── EC2 instance-profile role: resolved, never inferred ─────────────────────


@mock_aws
def test_ec2_instance_profile_role_resolved_via_get_instance_profile():
    iam = boto3.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(RoleName="ec2-role", AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    prof = iam.create_instance_profile(InstanceProfileName="ec2-prof")["InstanceProfile"]
    iam.add_role_to_instance_profile(InstanceProfileName="ec2-prof", RoleName="ec2-role")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                      IamInstanceProfile={"Arn": prof["Arn"]})

    result = Ec2Enumerator().enumerate(_client(), "us-east-1")
    edges = _edge_map(result)
    assert (prof["Arn"], role_arn, "InstanceProfileRole") in edges
    assert role_arn in {n.object_id for n in _nodes_of(result, NodeKind.IAM_ROLE)}


@mock_aws
def test_unresolvable_instance_profile_fabricates_no_role(monkeypatch):
    iam = boto3.client("iam", region_name="us-east-1")
    prof = iam.create_instance_profile(InstanceProfileName="p")["InstanceProfile"]
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                      IamInstanceProfile={"Arn": prof["Arn"]})

    client = _client()

    def denied(**kw):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetInstanceProfile")

    monkeypatch.setattr(client.client("iam"), "get_instance_profile", denied)

    result = Ec2Enumerator().enumerate(client, "us-east-1")
    # The profile membership edge is fine; NO role node / role edge is fabricated.
    assert not any(e.kind == "InstanceProfileRole" for e in result.edges)
    assert _nodes_of(result, NodeKind.IAM_ROLE) == []


# ─── structural references are not traversable pivots ────────────────────────


def test_structural_role_edges_absent_from_roam_hops():
    fn = "arn:aws:lambda:us-east-1:111:function:fn"
    role = "arn:aws:iam::111:role/exec"
    nodes = {
        fn: Node(fn, "fn", NodeKind.LAMBDA_FUNCTION),
        role: Node(role, "exec", NodeKind.IAM_ROLE),
    }
    edges = [Edge(fn, role, "LambdaExecutionRole")]
    hops = _roam_hops(AttackGraph(nodes, edges), fn)
    assert hops == []   # a structural exec-role reference is not a hop
