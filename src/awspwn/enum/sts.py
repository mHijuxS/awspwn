"""STS enumerator - resolve the calling identity and seed it as the graph's
source node.

Cheap, always-available, and the anchor for every attack path: `awspwn pwn`
starts from whoever you are right now.
"""

from __future__ import annotations

from ..aws_client import AwsClient, canonical_principal_id, resolve_role_arn
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

        # Persist the raw session ARN onto the live identity (creds propagation,
        # logging, and simulate need to know we are a *session*).
        client.identity.arn = arn or client.identity.arn
        client.identity.account = account or client.identity.account
        client.identity.user_id = user_id or client.identity.user_id

        # Key the graph node by the IAM principal ARN, not the STS session ARN,
        # so an assumed-role session lines up with the role node the IAM
        # enumerator (or a later pivot's edge target) mints. The raw session ARN
        # is retained as evidence.
        graph_arn = canonical_principal_id(arn) if arn else ""
        if graph_arn and graph_arn != arn:
            # An STS session ARN drops the IAM role PATH (a role at /team/app/Name
            # canonicalizes to :role/Name). GetRole resolves the real path-
            # qualified ARN when we hold the permission; otherwise the name-only
            # ARN is a best-effort key. Post-pivot this never matters - the chosen
            # edge target is the authoritative role ARN.
            graph_arn = self._resolve_role_path(client, graph_arn) or graph_arn

        kind = NodeKind.from_arn(graph_arn) if graph_arn else NodeKind.UNKNOWN
        props = {"is_caller": True, "user_id": user_id, "source": "sts"}
        if arn and graph_arn != arn:
            props["session_arn"] = arn  # evidence: the live STS session ARN

        node = Node(
            object_id=graph_arn or f"caller:{user_id}",
            name=graph_arn.rsplit("/", 1)[-1] if graph_arn else user_id,
            kind=kind,
            account=account,
            properties=props,
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

    @staticmethod
    def _resolve_role_path(client: AwsClient, name_only_arn: str) -> str:
        """Best-effort path-qualified role ARN. Delegates to the shared resolver so
        the GetRole logic is not duplicated between here and the self-policy
        resolver."""
        return resolve_role_arn(client, name_only_arn.rsplit("/", 1)[-1])
