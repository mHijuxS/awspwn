"""Secrets enumerator - Secrets Manager secrets and SSM Parameter Store
parameters. Metadata only; values are never fetched during read-only enum (that
is GetSecretValue, an exploitation step).
"""

from __future__ import annotations

import json

from ..aws_client import AwsClient
from ..models import Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator


class SecretsEnumerator(ServiceEnumerator):
    name = "secrets"
    service = "secretsmanager"
    is_global = False

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        account = client.identity.account

        # ── Secrets Manager ──
        sm = client.client("secretsmanager", region=region)
        try:
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for sec in page.get("SecretList", []):
                    arn = sec.get("ARN", "")
                    name = sec.get("Name", "")
                    props = {"description": sec.get("Description", "")}
                    result.nodes.append(
                        Node(object_id=arn, name=name, kind=NodeKind.SECRET, account=account, region=region, properties=props)
                    )
                    # Resource policy exposure
                    try:
                        rp = sm.get_resource_policy(SecretId=arn).get("ResourcePolicy")
                        if rp and _exposes_external(json.loads(rp), account):
                            result.findings.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    category="secrets",
                                    title=f"Secret readable by external account: {name}",
                                    detail="Resource policy grants access outside this account.",
                                    arn=arn,
                                )
                            )
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "secretsmanager:ListSecrets", region, result):
                raise

        # ── SSM Parameter Store (metadata only) ──
        ssm = client.client("ssm", region=region)
        try:
            paginator = ssm.get_paginator("describe_parameters")
            for page in paginator.paginate():
                for p in page.get("Parameters", []):
                    pname = p.get("Name", "")
                    arn = f"arn:aws:ssm:{region}:{account}:parameter{pname if pname.startswith('/') else '/' + pname}"
                    props = {"type": p.get("Type", "")}
                    result.nodes.append(
                        Node(object_id=arn, name=pname, kind=NodeKind.SSM_PARAMETER, account=account, region=region, properties=props)
                    )
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "ssm:DescribeParameters", region, result):
                raise

        return result


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
