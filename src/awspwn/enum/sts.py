"""STS enumerator - resolve the calling identity and seed it as the graph's
source node.

Cheap, always-available, and the anchor for every attack path: `awspwn pwn`
starts from whoever you are right now.
"""

from __future__ import annotations

from ..aws_client import AwsClient
from ..models import Node, NodeKind, Severity, Finding
from .base import EnumResult, ServiceEnumerator


class StsEnumerator(ServiceEnumerator):
    name = "sts"
    service = "sts"
    is_global = True

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        sts = client.client("sts")
        try:
            ident = sts.get_caller_identity()
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "sts:GetCallerIdentity", region, result):
                raise
            return result

        arn = ident.get("Arn", "")
        account = ident.get("Account", "")
        user_id = ident.get("UserId", "")

        # Persist onto the live identity so downstream context is populated.
        client.identity.arn = arn or client.identity.arn
        client.identity.account = account or client.identity.account
        client.identity.user_id = user_id or client.identity.user_id

        kind = NodeKind.from_arn(arn) if arn else NodeKind.UNKNOWN
        # Assumed-role sessions present as arn:aws:sts::acct:assumed-role/Name/session
        if ":assumed-role/" in arn:
            kind = NodeKind.IAM_ROLE

        node = Node(
            object_id=arn or f"caller:{user_id}",
            name=arn.rsplit("/", 1)[-1] if arn else user_id,
            kind=kind,
            account=account,
            properties={"is_caller": True, "user_id": user_id, "source": "sts"},
        )
        result.nodes.append(node)
        result.findings.append(
            Finding(
                severity=Severity.INFO,
                category="identity",
                title="Caller identity resolved",
                detail=f"{arn or user_id} in account {account}",
                arn=arn,
            )
        )
        return result
