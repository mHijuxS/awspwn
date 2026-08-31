"""RDS enumerator - DB instances and snapshots, including public/shared
snapshot exposure (a common way sensitive data leaks out of an account).
"""

from __future__ import annotations

from ..aws_client import AwsClient
from ..models import Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator


class RdsEnumerator(ServiceEnumerator):
    name = "rds"
    service = "rds"
    is_global = False

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        rds = client.client("rds", region=region)
        account = client.identity.account

        try:
            for page in rds.get_paginator("describe_db_instances").paginate():
                for db in page.get("DBInstances", []):
                    ident = db.get("DBInstanceIdentifier", "")
                    arn = db.get("DBInstanceArn", f"arn:aws:rds:{region}:{account}:db:{ident}")
                    props = {
                        "engine": db.get("Engine", ""),
                        "public": db.get("PubliclyAccessible", False),
                        "iam_auth": db.get("IAMDatabaseAuthenticationEnabled", False),
                        "endpoint": db.get("Endpoint", {}).get("Address", ""),
                    }
                    result.nodes.append(
                        Node(object_id=arn, name=ident, kind=NodeKind.RDS_INSTANCE, account=account, region=region, properties=props)
                    )
                    if props["public"]:
                        result.findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                category="rds",
                                title=f"Publicly accessible RDS instance: {ident}",
                                detail="DB is reachable from the internet (still requires network + auth).",
                                arn=arn,
                            )
                        )
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "rds:DescribeDBInstances", region, result):
                raise

        try:
            for page in rds.get_paginator("describe_db_snapshots").paginate():
                for snap in page.get("DBSnapshots", []):
                    sid = snap.get("DBSnapshotIdentifier", "")
                    arn = snap.get("DBSnapshotArn", f"arn:aws:rds:{region}:{account}:snapshot:{sid}")
                    props = {"encrypted": snap.get("Encrypted", False)}
                    public = False
                    try:
                        attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
                        for a in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
                            if a.get("AttributeName") == "restore":
                                vals = a.get("AttributeValues", [])
                                if "all" in vals:
                                    public = True
                                    props["public"] = True
                                elif vals:
                                    props["shared_with"] = vals
                    except Exception:  # noqa: BLE001
                        pass
                    result.nodes.append(
                        Node(object_id=arn, name=sid, kind=NodeKind.RDS_SNAPSHOT, account=account, region=region, properties=props)
                    )
                    if public:
                        result.findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                category="rds",
                                title=f"Public RDS snapshot: {sid}",
                                detail="Snapshot is restorable by any AWS account.",
                                arn=arn,
                            )
                        )
                    elif props.get("shared_with"):
                        result.findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                category="rds",
                                title=f"RDS snapshot shared externally: {sid}",
                                detail=f"Shared with: {', '.join(props['shared_with'])}",
                                arn=arn,
                            )
                        )
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "rds:DescribeDBSnapshots", region, result):
                raise

        return result
