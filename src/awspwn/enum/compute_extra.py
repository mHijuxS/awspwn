"""ECS / EKS / ECR enumerator - container attack surface: clusters, task
definitions (+ their task roles), EKS clusters, and ECR repositories with
external repository policies.
"""

from __future__ import annotations

import json

from ..aws_client import AwsClient
from ..models import Edge, Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator, minimal_role_node


class ComputeExtraEnumerator(ServiceEnumerator):
    name = "compute_extra"
    service = "ecs"
    is_global = False

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        account = client.identity.account
        self._ecs(client, region, account, result)
        self._eks(client, region, account, result)
        self._ecr(client, region, account, result)
        return result

    def _ecs(self, client, region, account, result):
        ecs = client.client("ecs", region=region)
        try:
            clusters = []
            for page in ecs.get_paginator("list_clusters").paginate():
                clusters.extend(page.get("clusterArns", []))
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "ecs:ListClusters", region, result):
                raise
            return
        for carn in clusters:
            result.nodes.append(
                Node(object_id=carn, name=carn.rsplit("/", 1)[-1], kind=NodeKind.ECS_CLUSTER, account=account, region=region, properties={})
            )
        # Task definitions and their task roles
        try:
            for page in ecs.get_paginator("list_task_definitions").paginate():
                for tdarn in page.get("taskDefinitionArns", []):
                    try:
                        td = ecs.describe_task_definition(taskDefinition=tdarn).get("taskDefinition", {})
                    except Exception:  # noqa: BLE001
                        continue
                    role_arn = td.get("taskRoleArn", "")
                    exec_arn = td.get("executionRoleArn", "")
                    props = {"task_role": role_arn, "execution_role": exec_arn}
                    result.nodes.append(
                        Node(object_id=tdarn, name=td.get("family", tdarn.rsplit("/", 1)[-1]),
                             kind=NodeKind.ECS_TASK_DEF, account=account, region=region, properties=props)
                    )
                    # The TASK role is the workload identity a running task assumes.
                    if role_arn and ":role/" in role_arn:
                        result.nodes.append(minimal_role_node(role_arn))
                        result.edges.append(Edge(tdarn, role_arn, "ECSTaskRole", {}))
                    # The EXECUTION role is used by the ECS agent (pull images, write
                    # logs), NOT the workload identity - kept as structural metadata,
                    # never an identity pivot.
                    if exec_arn and ":role/" in exec_arn and exec_arn != role_arn:
                        result.nodes.append(minimal_role_node(exec_arn))
                        result.edges.append(Edge(tdarn, exec_arn, "ECSExecutionRole", {}))
        except Exception as exc:  # noqa: BLE001
            self._handle(exc, "ecs:ListTaskDefinitions", region, result)

    def _eks(self, client, region, account, result):
        eks = client.client("eks", region=region)
        try:
            clusters = []
            for page in eks.get_paginator("list_clusters").paginate():
                clusters.extend(page.get("clusters", []))
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "eks:ListClusters", region, result):
                raise
            return
        for name in clusters:
            arn = f"arn:aws:eks:{region}:{account}:cluster/{name}"
            props = {}
            try:
                desc = eks.describe_cluster(name=name).get("cluster", {})
                endpoint_public = desc.get("resourcesVpcConfig", {}).get("endpointPublicAccess", False)
                props["endpoint_public"] = endpoint_public
                if endpoint_public:
                    result.findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="eks",
                            title=f"EKS cluster with public API endpoint: {name}",
                            detail="Kubernetes API server is reachable from the internet.",
                            arn=arn,
                        )
                    )
            except Exception:  # noqa: BLE001
                pass
            result.nodes.append(
                Node(object_id=arn, name=name, kind=NodeKind.EKS_CLUSTER, account=account, region=region, properties=props)
            )

    def _ecr(self, client, region, account, result):
        ecr = client.client("ecr", region=region)
        try:
            repos = []
            for page in ecr.get_paginator("describe_repositories").paginate():
                repos.extend(page.get("repositories", []))
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "ecr:DescribeRepositories", region, result):
                raise
            return
        for repo in repos:
            arn = repo.get("repositoryArn", "")
            name = repo.get("repositoryName", "")
            result.nodes.append(
                Node(object_id=arn, name=name, kind=NodeKind.ECR_REPOSITORY, account=account, region=region, properties={})
            )
            try:
                pol = json.loads(ecr.get_repository_policy(repositoryName=name).get("policyText", "{}"))
                if _exposes_external(pol, account):
                    result.findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="ecr",
                            title=f"ECR repository pullable by external account: {name}",
                            detail="Repository policy grants access outside this account.",
                            arn=arn,
                        )
                    )
            except Exception:  # noqa: BLE001
                pass


def _exposes_external(policy: dict, account: str) -> bool:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            return True
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        vals = aws if isinstance(aws, list) else ([aws] if aws else [])
        for v in vals:
            if v == "*" or (account and account not in str(v)):
                return True
    return False
