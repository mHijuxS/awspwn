"""Authoritative effective-permission checks via iam:SimulatePrincipalPolicy.

AWS's own evaluator handles wildcards, NotAction/NotResource, explicit-deny
precedence, permission boundaries, SCPs, and most condition keys - everything
the offline matcher in enum/iam.py cannot. Use this to CONFIRM candidate privesc
edges when the caller holds iam:SimulatePrincipalPolicy.

Note: moto does not implement SimulatePrincipalPolicy, so unit tests stub it;
on a real engagement the caller often lacks it too. It is therefore an
opportunistic refinement, never a hard dependency.
"""

from __future__ import annotations

from typing import Optional

from ..aws_client import AwsClient, is_access_denied


# Privesc-relevant actions worth simulating per principal.
PRIVESC_ACTIONS = [
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "ec2:RunInstances",
    "ssm:SendCommand",
    "secretsmanager:GetSecretValue",
]


def simulate_principal(
    client: AwsClient,
    principal_arn: str,
    actions: Optional[list[str]] = None,
    resource_arns: Optional[list[str]] = None,
) -> dict[str, bool]:
    """Return {action: allowed} for a principal, or {} if simulation is denied.

    Empty dict signals "could not simulate" - callers should fall back to the
    offline matcher's result rather than treating it as "everything denied".
    """
    actions = actions or PRIVESC_ACTIONS
    iam = client.client("iam")
    kwargs = {"PolicySourceArn": principal_arn, "ActionNames": actions}
    if resource_arns:
        kwargs["ResourceArns"] = resource_arns
    try:
        results: dict[str, bool] = {}
        paginator = iam.get_paginator("simulate_principal_policy")
        for page in paginator.paginate(**kwargs):
            for res in page.get("EvaluationResults", []):
                name = res.get("EvalActionName", "")
                decision = res.get("EvalDecision", "")
                results[name] = decision == "allowed"
        return results
    except Exception as exc:  # noqa: BLE001
        if is_access_denied(exc):
            return {}
        return {}


def can(client: AwsClient, principal_arn: str, action: str, resource: str = "*") -> Optional[bool]:
    """Single-action check. Returns None if simulation is unavailable."""
    res = simulate_principal(client, principal_arn, [action], [resource] if resource else None)
    return res.get(action) if res else None
