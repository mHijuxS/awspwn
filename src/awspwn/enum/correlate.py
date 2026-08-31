"""Post-enumeration correlation - mint principal -> resource edges.

Enumerators run in parallel and are blind to each other, so resource-access
edges (a principal that can read a secret, scan a table, run a command on an
instance) cannot be minted inside any single enumerator. This pass runs after
the fan-out, matching each principal's stored action patterns against the
enumerated resource nodes.

Best-effort: it uses the action patterns captured during IAM enumeration and
does not re-evaluate resource policies or conditions. policy/simulate.py refines
these authoritatively when simulation is available.
"""

from __future__ import annotations

import re

from ..models import Edge, Node, NodeKind


def _action_regex(pattern: str) -> re.Pattern:
    esc = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile("^" + esc + "$", re.IGNORECASE)


# (required action, target NodeKind, edge kind). All actions must be allowed.
_RESOURCE_RULES: list[tuple[list[str], NodeKind, str]] = [
    (["secretsmanager:GetSecretValue"], NodeKind.SECRET, "GetSecretValue"),
    (["ssm:GetParameter"], NodeKind.SSM_PARAMETER, "ReadSSMParameter"),
    (["s3:GetObject"], NodeKind.S3_BUCKET, "ReadS3Object"),
    (["s3:ListBucket"], NodeKind.S3_BUCKET, "ListS3Bucket"),
    (["s3:PutObject"], NodeKind.S3_BUCKET, "WriteS3Object"),
    (["dynamodb:Scan"], NodeKind.DYNAMODB_TABLE, "DynamoDBScan"),
    (["kms:Decrypt"], NodeKind.KMS_KEY, "KMSDecrypt"),
    (["ssm:SendCommand"], NodeKind.EC2_INSTANCE, "SSMSendCommand"),
    (["ssm:StartSession"], NodeKind.EC2_INSTANCE, "SSMStartSession"),
    (["lambda:UpdateFunctionCode"], NodeKind.LAMBDA_FUNCTION, "UpdateLambdaCode"),
    (["lambda:InvokeFunction"], NodeKind.LAMBDA_FUNCTION, "InvokeLambda"),
    (["logs:FilterLogEvents"], NodeKind.CLOUDWATCH_LOG_GROUP, "ReadCloudWatchLogs"),
    (["ecr:GetAuthorizationToken", "ecr:BatchGetImage"], NodeKind.ECR_REPOSITORY, "ECRGetLoginPull"),
    (["rds:RestoreDBInstanceFromDBSnapshot"], NodeKind.RDS_SNAPSHOT, "RestoreRDSFromSnapshot"),
    (["ec2:CreateSnapshot"], NodeKind.EBS_VOLUME, "CreateEBSSnapshot"),
]


def _allows_all(patterns: list[str], actions: list[str]) -> bool:
    compiled = [_action_regex(p) for p in patterns]
    for action in actions:
        if not any(rx.match(action) for rx in compiled):
            return False
    return True


def correlate_resource_edges(nodes: list[Node], edges: list[Edge]) -> list[Edge]:
    """Return new principal -> resource edges to append to the graph."""
    principals = [
        n for n in nodes if n.is_principal and n.properties.get("action_patterns")
    ]
    resources_by_kind: dict[NodeKind, list[Node]] = {}
    for n in nodes:
        resources_by_kind.setdefault(n.kind, []).append(n)

    existing = {(e.source_id, e.target_id, e.kind) for e in edges}
    new_edges: list[Edge] = []

    for principal in principals:
        patterns = principal.properties.get("action_patterns", [])
        for actions, kind, edge_kind in _RESOURCE_RULES:
            targets = resources_by_kind.get(kind)
            if not targets:
                continue
            if not _allows_all(patterns, actions):
                continue
            for target in targets:
                key = (principal.object_id, target.object_id, edge_kind)
                if key in existing:
                    continue
                existing.add(key)
                new_edges.append(
                    Edge(
                        principal.object_id,
                        target.object_id,
                        edge_kind,
                        {"via": "correlation"},
                    )
                )
    return new_edges
