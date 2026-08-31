"""EC2 enumerator - instances (+ their instance roles), snapshots, security
groups. Surfaces IMDSv1, public snapshots, and instance-attached roles that
compute lateral movement can pivot through.
"""

from __future__ import annotations

from ..aws_client import AwsClient
from ..models import Edge, Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator


class Ec2Enumerator(ServiceEnumerator):
    name = "ec2"
    service = "ec2"
    is_global = False

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        ec2 = client.client("ec2", region=region)
        account = client.identity.account

        # ── Instances ──
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        self._instance(inst, account, region, result)
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "ec2:DescribeInstances", region, result):
                raise

        # ── Snapshots owned by this account ──
        try:
            snaps = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
            for snap in snaps:
                # Belt-and-suspenders: only our own snapshots (some mocks/older
                # API behaviours ignore OwnerIds and return public ones too).
                if account and snap.get("OwnerId") and snap["OwnerId"] != account:
                    continue
                self._snapshot(ec2, snap, account, region, result)
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "ec2:DescribeSnapshots", region, result):
                raise

        return result

    def _instance(self, inst: dict, account: str, region: str, result: EnumResult) -> None:
        iid = inst.get("InstanceId", "")
        arn = f"arn:aws:ec2:{region}:{account}:instance/{iid}"
        state = inst.get("State", {}).get("Name", "")
        imds = inst.get("MetadataOptions", {}).get("HttpTokens", "")
        props = {
            "state": state,
            "private_ip": inst.get("PrivateIpAddress", ""),
            "public_ip": inst.get("PublicIpAddress", ""),
            "imdsv1": imds == "optional",
        }
        result.nodes.append(
            Node(object_id=arn, name=iid, kind=NodeKind.EC2_INSTANCE, account=account, region=region, properties=props)
        )

        # Instance profile -> role structural edge (a pivot for IMDS theft).
        profile = inst.get("IamInstanceProfile", {})
        prof_arn = profile.get("Arn", "")
        if prof_arn:
            # Profile arn: arn:aws:iam::acct:instance-profile/Name
            result.nodes.append(
                Node(object_id=prof_arn, name=prof_arn.rsplit("/", 1)[-1],
                     kind=NodeKind.INSTANCE_PROFILE, account=account, properties={})
            )
            result.edges.append(Edge(arn, prof_arn, "InstanceProfileFor", {}))
            # IMDS creds edge: whoever runs code on the instance gets the role.
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="ec2",
                    title=f"Instance {iid} carries an instance profile",
                    detail="Code execution on this host yields the instance role via IMDS.",
                    arn=arn,
                    evidence=prof_arn,
                )
            )

        if props["imdsv1"] and props.get("public_ip"):
            result.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="ec2",
                    title=f"Public instance {iid} allows IMDSv1",
                    detail="IMDSv1 + a public IP is the classic SSRF -> instance-credential path.",
                    arn=arn,
                )
            )

    def _snapshot(self, ec2, snap: dict, account: str, region: str, result: EnumResult) -> None:
        sid = snap.get("SnapshotId", "")
        arn = f"arn:aws:ec2:{region}:{account}:snapshot/{sid}"
        props = {"encrypted": snap.get("Encrypted", False), "volume_id": snap.get("VolumeId", "")}
        public = False
        try:
            attr = ec2.describe_snapshot_attribute(SnapshotId=sid, Attribute="createVolumePermission")
            perms = attr.get("CreateVolumePermissions", [])
            if any(p.get("Group") == "all" for p in perms):
                public = True
                props["public"] = True
            shared = [p.get("UserId") for p in perms if p.get("UserId")]
            if shared:
                props["shared_with"] = shared
        except Exception:  # noqa: BLE001
            pass

        result.nodes.append(
            Node(object_id=arn, name=sid, kind=NodeKind.EBS_SNAPSHOT, account=account, region=region, properties=props)
        )
        if public:
            result.findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="ec2",
                    title=f"Public EBS snapshot: {sid}",
                    detail="Snapshot is shared with all AWS accounts - anyone can restore and read its disk.",
                    arn=arn,
                )
            )
        elif props.get("shared_with"):
            result.findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="ec2",
                    title=f"EBS snapshot shared externally: {sid}",
                    detail=f"Shared with account(s): {', '.join(props['shared_with'])}",
                    arn=arn,
                )
            )
