"""Lambda enumerator - functions, their execution roles, and resource policies
(which can expose invoke access to external accounts).
"""

from __future__ import annotations

import json

from ..aws_client import AwsClient
from ..models import Edge, Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator


class LambdaEnumerator(ServiceEnumerator):
    name = "lambda"
    service = "lambda"
    is_global = False

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        lam = client.client("lambda", region=region)
        account = client.identity.account

        try:
            paginator = lam.get_paginator("list_functions")
            functions = []
            for page in paginator.paginate():
                functions.extend(page.get("Functions", []))
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "lambda:ListFunctions", region, result):
                raise
            return result

        for fn in functions:
            name = fn.get("FunctionName", "")
            arn = fn.get("FunctionArn", "")
            role_arn = fn.get("Role", "")
            env = fn.get("Environment", {}).get("Variables", {})
            props = {"runtime": fn.get("Runtime", ""), "role_arn": role_arn}
            # Env vars frequently hold secrets.
            suspicious = [k for k in env if any(t in k.upper() for t in ("KEY", "SECRET", "TOKEN", "PASS"))]
            if suspicious:
                props["suspicious_env"] = suspicious

            result.nodes.append(
                Node(object_id=arn, name=name, kind=NodeKind.LAMBDA_FUNCTION, account=account, region=region, properties=props)
            )
            # Function runs as its execution role -> structural edge to the role.
            if role_arn:
                result.edges.append(Edge(arn, role_arn, "InstanceProfileFor", {"via": "lambda-exec-role"}))

            if suspicious:
                result.findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="lambda",
                        title=f"Lambda {name} has credential-shaped env vars",
                        detail=f"Environment variables: {', '.join(suspicious)}",
                        arn=arn,
                    )
                )

            # Resource policy - external invoke exposure.
            try:
                pol = json.loads(lam.get_policy(FunctionName=name)["Policy"])
                if _exposes_external(pol, account):
                    result.findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="lambda",
                            title=f"Lambda {name} invokable by an external principal",
                            detail="Resource policy grants lambda:InvokeFunction outside this account.",
                            arn=arn,
                        )
                    )
            except Exception:  # noqa: BLE001 - no policy is normal
                pass

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
