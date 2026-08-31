"""S3 enumerator - buckets, policies, ACLs, public-access posture.

Public / externally-shared buckets are among the highest-value findings on a
cloud engagement, so this leans hard on surfacing exposure.
"""

from __future__ import annotations

import json

from ..aws_client import AwsClient
from ..models import Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator


class S3Enumerator(ServiceEnumerator):
    name = "s3"
    service = "s3"
    is_global = True

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        s3 = client.client("s3")
        account = client.identity.account

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "s3:ListAllMyBuckets", "", result):
                raise
            return result

        for b in buckets:
            name = b["Name"]
            arn = f"arn:aws:s3:::{name}"
            props: dict = {}
            public = False

            # Public access block
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                props["public_access_block"] = pab
                if not all(pab.values()):
                    props["pab_incomplete"] = True
            except Exception:  # noqa: BLE001 - no PAB configured is itself notable
                props["pab_incomplete"] = True

            # Bucket policy
            try:
                pol = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
                ext, wild = _policy_exposes_external(pol, account)
                if wild:
                    public = True
                    props["public"] = True
                if ext:
                    props["shares_external"] = True
            except Exception:  # noqa: BLE001 - no policy is fine
                pass

            # ACL
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        public = True
                        props["public"] = True
                        props["public_acl"] = True
            except Exception:  # noqa: BLE001
                pass

            result.nodes.append(
                Node(object_id=arn, name=name, kind=NodeKind.S3_BUCKET, account=account, properties=props)
            )

            if public:
                result.findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="s3",
                        title=f"Public S3 bucket: {name}",
                        detail="Bucket is world-readable/writable via ACL or bucket policy.",
                        arn=arn,
                    )
                )
            elif props.get("shares_external"):
                result.findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="s3",
                        title=f"S3 bucket shared with external account: {name}",
                        detail="Bucket policy grants access to a principal outside this account.",
                        arn=arn,
                    )
                )

        return result


def _policy_exposes_external(policy: dict, account: str) -> tuple[bool, bool]:
    """Return (shares_external, public_wildcard) for a resource policy."""
    ext = False
    wild = False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            wild = True
            continue
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        vals = aws if isinstance(aws, list) else ([aws] if aws else [])
        for v in vals:
            if v == "*":
                wild = True
            elif account and account not in str(v):
                ext = True
    return ext, wild
