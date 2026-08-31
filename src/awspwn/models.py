"""Data models for AWSPwn - AWS attack-path automation.

Mirrors ADPwn's models.py (Node/Edge/AttackPath/AbuseStep/AbuseInfo) and adds:
  * AwsIdentity  - the credential bag, AWS analogue of ADPwn's loose context keys
  * BlastRadius  - per-step safety classification (no ADPwn analogue; AWS mutates
                   real, billable, CloudTrail-logged accounts)
  * Mutation     - rollback ledger entry for every state-changing API call
  * Severity/Finding - ADScout's reporting model
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Optional


# ─── Operator platform (kept for AbuseStep parity with ADPwn) ───────────────


class Platform(Enum):
    LINUX = "linux"
    WINDOWS = "windows"


# ─── Blast radius - the safety axis ────────────────────────────────────────


class BlastRadius(Enum):
    """How much damage a step can do. Gates execution in `awspwn pwn`.

    READ              - no state change (Get/List/Describe, sts:AssumeRole).
    MUTATE            - reversible state change with a registered undo.
    DESTRUCTIVE       - deletes or overwrites something the account needs.
    EXTERNAL_EXPOSURE - grants access to a principal outside the account.
    """

    READ = "READ"
    MUTATE = "MUTATE"
    DESTRUCTIVE = "DESTRUCTIVE"
    EXTERNAL_EXPOSURE = "EXTERNAL_EXPOSURE"


# Extra pathfinding cost per blast radius, so the graph prefers the quietest
# route to admin. ADPwn has no analogue - every AD abuse is equally noisy.
BLAST_SURCHARGE: dict[BlastRadius, int] = {
    BlastRadius.READ: 0,
    BlastRadius.MUTATE: 1,
    BlastRadius.DESTRUCTIVE: 3,
    BlastRadius.EXTERNAL_EXPOSURE: 3,
}


# ─── Node kinds ────────────────────────────────────────────────────────────


class NodeKind(Enum):
    # Identity
    AWS_ACCOUNT = "AWSAccount"
    ROOT_USER = "RootUser"
    IAM_USER = "IAMUser"
    IAM_ROLE = "IAMRole"
    IAM_GROUP = "IAMGroup"
    IAM_POLICY = "IAMPolicy"
    INSTANCE_PROFILE = "InstanceProfile"
    FEDERATED_PRINCIPAL = "FederatedPrincipal"
    SSO_PERMISSION_SET = "SSOPermissionSet"
    SSO_PRINCIPAL = "SSOPrincipal"
    EXTERNAL_ACCOUNT = "ExternalAccount"
    SERVICE_PRINCIPAL = "ServicePrincipal"
    # Compute
    EC2_INSTANCE = "EC2Instance"
    LAMBDA_FUNCTION = "LambdaFunction"
    ECS_CLUSTER = "ECSCluster"
    ECS_TASK_DEF = "ECSTaskDefinition"
    EKS_CLUSTER = "EKSCluster"
    AUTOSCALING_GROUP = "AutoScalingGroup"
    CLOUDFORMATION_STACK = "CloudFormationStack"
    GLUE_DEV_ENDPOINT = "GlueDevEndpoint"
    SAGEMAKER_NOTEBOOK = "SageMakerNotebook"
    CODEBUILD_PROJECT = "CodeBuildProject"
    ECR_REPOSITORY = "ECRRepository"
    # Data & secrets
    S3_BUCKET = "S3Bucket"
    SECRET = "Secret"
    SSM_PARAMETER = "SSMParameter"
    RDS_INSTANCE = "RDSInstance"
    RDS_SNAPSHOT = "RDSSnapshot"
    EBS_VOLUME = "EBSVolume"
    EBS_SNAPSHOT = "EBSSnapshot"
    DYNAMODB_TABLE = "DynamoDBTable"
    KMS_KEY = "KMSKey"
    CLOUDWATCH_LOG_GROUP = "CloudWatchLogGroup"
    # Org
    ORGANIZATION = "Organization"
    ORG_UNIT = "OrganizationalUnit"
    SCP = "ServiceControlPolicy"
    IDENTITY_CENTER = "IdentityCenter"

    UNKNOWN = "Unknown"

    @classmethod
    def from_str(cls, value: str) -> "NodeKind":
        if not value:
            return cls.UNKNOWN
        for member in cls:
            if member.value.lower() == value.lower():
                return member
        # Tolerate enum-member spellings ("IAM_USER") and bare forms ("user")
        normalized = value.replace("-", "_").replace(" ", "_").upper()
        for member in cls:
            if member.name == normalized:
                return member
        return cls.UNKNOWN

    @classmethod
    def from_arn(cls, arn: str) -> "NodeKind":
        """Infer a node kind from an ARN's service + resource-type segments.

        arn:partition:service:region:account:resource-type/resource-id
        """
        if not arn.startswith("arn:"):
            return cls.UNKNOWN
        parts = arn.split(":", 5)
        if len(parts) < 6:
            return cls.UNKNOWN
        service, resource = parts[2], parts[5]
        rtype = resource.split("/", 1)[0].split(":", 1)[0]
        return _ARN_KIND_MAP.get((service, rtype), _ARN_SERVICE_MAP.get(service, cls.UNKNOWN))


_ARN_KIND_MAP: dict[tuple[str, str], NodeKind] = {
    ("iam", "user"): NodeKind.IAM_USER,
    ("iam", "role"): NodeKind.IAM_ROLE,
    ("iam", "group"): NodeKind.IAM_GROUP,
    ("iam", "policy"): NodeKind.IAM_POLICY,
    ("iam", "instance-profile"): NodeKind.INSTANCE_PROFILE,
    ("iam", "root"): NodeKind.ROOT_USER,
    ("iam", "saml-provider"): NodeKind.FEDERATED_PRINCIPAL,
    ("iam", "oidc-provider"): NodeKind.FEDERATED_PRINCIPAL,
    ("ec2", "instance"): NodeKind.EC2_INSTANCE,
    ("ec2", "volume"): NodeKind.EBS_VOLUME,
    ("ec2", "snapshot"): NodeKind.EBS_SNAPSHOT,
    ("ecs", "cluster"): NodeKind.ECS_CLUSTER,
    ("ecs", "task-definition"): NodeKind.ECS_TASK_DEF,
    ("eks", "cluster"): NodeKind.EKS_CLUSTER,
    ("rds", "db"): NodeKind.RDS_INSTANCE,
    ("rds", "snapshot"): NodeKind.RDS_SNAPSHOT,
    ("dynamodb", "table"): NodeKind.DYNAMODB_TABLE,
    ("kms", "key"): NodeKind.KMS_KEY,
    ("logs", "log-group"): NodeKind.CLOUDWATCH_LOG_GROUP,
    ("organizations", "ou"): NodeKind.ORG_UNIT,
    ("organizations", "policy"): NodeKind.SCP,
    ("sso", "permissionSet"): NodeKind.SSO_PERMISSION_SET,
}

_ARN_SERVICE_MAP: dict[str, NodeKind] = {
    "s3": NodeKind.S3_BUCKET,
    "lambda": NodeKind.LAMBDA_FUNCTION,
    "secretsmanager": NodeKind.SECRET,
    "ssm": NodeKind.SSM_PARAMETER,
    "ecr": NodeKind.ECR_REPOSITORY,
    "cloudformation": NodeKind.CLOUDFORMATION_STACK,
    "glue": NodeKind.GLUE_DEV_ENDPOINT,
    "sagemaker": NodeKind.SAGEMAKER_NOTEBOOK,
    "codebuild": NodeKind.CODEBUILD_PROJECT,
    "autoscaling": NodeKind.AUTOSCALING_GROUP,
}


# Kinds that can hold credentials - i.e. reaching them may change your identity.
PRINCIPAL_KINDS: frozenset[NodeKind] = frozenset(
    {
        NodeKind.ROOT_USER,
        NodeKind.IAM_USER,
        NodeKind.IAM_ROLE,
        NodeKind.SSO_PERMISSION_SET,
        NodeKind.SSO_PRINCIPAL,
        NodeKind.FEDERATED_PRINCIPAL,
    }
)


# ─── Permission-snapshot merge (authority-aware) ────────────────────────────

# Grant/permission properties whose merge is authority-aware, NOT last-writer-
# wins. `grant_read_status` records how complete the snapshot is: "complete"
# (authoritative - grant_statements + authoritative display, retraction allowed),
# "partial" (non-authoritative evidence - the *_partial keys, additive only), or
# absent (no self-read; legacy grant_statements are treated as complete).
GRANT_PROPERTY_KEYS = frozenset({
    "grant_read_status",
    "grant_statements", "attached_policies", "action_patterns", "is_admin",
    "grant_statements_partial", "attached_policies_partial", "action_patterns_partial",
})

_COMPLETE_KEYS = ("grant_read_status", "grant_statements", "attached_policies", "action_patterns", "is_admin")
_PARTIAL_KEYS = ("grant_statements_partial", "attached_policies_partial", "action_patterns_partial")


def merge_grant_properties(existing: dict, incoming: dict) -> None:
    """Merge the permission-snapshot keys of `incoming` into `existing` in place,
    respecting snapshot authority so a later partial read can never downgrade,
    overwrite, or make internally inconsistent a prior complete snapshot.

      * incoming complete  -> supersede: take its authoritative fields and DROP any
        stale partial evidence.
      * incoming partial    -> if `existing` already holds a complete snapshot
        (authoritative grant_statements), the partial evidence is dropped (a
        complete read fully describes the principal); otherwise store it as
        non-authoritative evidence.
      * incoming none        -> leave existing grant knowledge untouched.

    Tradeoff (deliberate, conservative): a NEWER partial observation cannot augment
    an OLDER complete snapshot - the partial is dropped rather than combined,
    because we cannot tell whether the complete set is silent about a resource or
    explicitly denies it, and combining could resurrect authoritatively-denied
    access. Consequence: a permission CHANGE seen only by a later partial read
    stays undiscovered until another COMPLETE read of that principal.
    """
    in_status = incoming.get("grant_read_status")
    # A legacy incoming (grant_statements, no status) is a complete snapshot.
    if in_status is None and "grant_statements" in incoming:
        in_status = "complete"
    if in_status == "complete":
        for k in _COMPLETE_KEYS:
            if k in incoming:
                existing[k] = incoming[k]
        for k in _PARTIAL_KEYS:
            existing.pop(k, None)
        return
    if in_status == "partial":
        if "grant_statements" in existing:
            return  # keep the authoritative snapshot; partial adds nothing trusted
        for k in ("grant_read_status", *_PARTIAL_KEYS):
            if k in incoming:
                existing[k] = incoming[k]
        return
    # in_status is None: incoming carries no self-read - preserve prior knowledge.


# ─── Graph primitives (ADPwn parity) ───────────────────────────────────────


@dataclass
class Node:
    """A principal or resource. `object_id` is the ARN wherever one exists."""

    object_id: str
    name: str = ""
    kind: NodeKind = NodeKind.UNKNOWN
    account: str = ""
    region: str = ""
    properties: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or self.object_id

    @property
    def is_principal(self) -> bool:
        return self.kind in PRINCIPAL_KINDS

    def __hash__(self):
        return hash(self.object_id)

    def __eq__(self, other):
        if isinstance(other, Node):
            return self.object_id == other.object_id
        return False

    def to_dict(self) -> dict:
        return {
            "object_id": self.object_id,
            "name": self.name,
            "kind": self.kind.value,
            "account": self.account,
            "region": self.region,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Node":
        return cls(
            object_id=d["object_id"],
            name=d.get("name", ""),
            kind=NodeKind.from_str(d.get("kind", "")),
            account=d.get("account", ""),
            region=d.get("region", ""),
            properties=d.get("properties", {}) or {},
        )


@dataclass
class Edge:
    """`source_id` can perform `kind` against `target_id`.

    `kind` is a plain str (ADPwn convention) so edge modules stay additive.
    `conditional` marks edges minted from a policy carrying Condition keys we
    could not evaluate - the action may not actually be permitted at runtime.
    """

    source_id: str
    target_id: str
    kind: str
    properties: dict = field(default_factory=dict)
    conditional: bool = False

    def __hash__(self):
        return hash((self.source_id, self.target_id, self.kind))

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "kind": self.kind,
            "properties": self.properties,
            "conditional": self.conditional,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Edge":
        return cls(
            source_id=d["source_id"],
            target_id=d["target_id"],
            kind=d["kind"],
            properties=d.get("properties", {}) or {},
            conditional=d.get("conditional", False),
        )


@dataclass
class AttackPath:
    nodes: list[Node]
    edges: list[Edge]
    cost: int = 0

    @property
    def length(self) -> int:
        return len(self.edges)

    def describe(self) -> str:
        parts = []
        for i, edge in enumerate(self.edges):
            src = self.nodes[i].label
            dst = self.nodes[i + 1].label
            parts.append(f"{src} --[{edge.kind}]--> {dst}")
        return "\n".join(parts)

    def to_dict(self) -> dict:
        return {
            "cost": self.cost,
            "length": self.length,
            "nodes": [n.object_id for n in self.nodes],
            "edges": [e.kind for e in self.edges],
        }


# ─── Abuse database primitives (ADPwn parity + blast radius) ───────────────


@dataclass
class AbuseStep:
    description: str
    command: str
    platform: Platform = Platform.LINUX
    tool: str = "aws"
    blast_radius: BlastRadius = BlastRadius.READ
    opsec_note: str = ""
    is_cleanup: bool = False
    # API this step calls, e.g. "iam:AttachUserPolicy" - drives the undo ledger.
    api: str = ""

    @property
    def mutating(self) -> bool:
        return self.blast_radius != BlastRadius.READ


@dataclass
class AbuseInfo:
    edge_kind: str
    description: str
    linux_steps: list[AbuseStep] = field(default_factory=list)
    windows_steps: list[AbuseStep] = field(default_factory=list)
    required_permissions: list[str] = field(default_factory=list)
    opsec_considerations: str = ""
    references: list[str] = field(default_factory=list)
    source_kinds: list[str] = field(default_factory=list)
    target_kinds: list[str] = field(default_factory=list)
    is_abusable: bool = True
    # Worst blast radius across all steps - used by the graph cost function.
    blast_radius: BlastRadius = BlastRadius.READ


# ─── Credentials ───────────────────────────────────────────────────────────


@dataclass
class AwsIdentity:
    """A set of AWS credentials plus the principal they resolve to.

    The AWS analogue of ADPwn's ATTACKER_NAME/ATTACKER_PASS/NTLM_HASH context
    keys, but typed - because `sts:AssumeRole` hands back a structured triple
    rather than something we have to regex out of stdout.
    """

    access_key: str = ""
    secret_key: str = ""
    session_token: str = ""
    profile: str = ""
    arn: str = ""
    account: str = ""
    user_id: str = ""
    region: str = "us-east-1"
    expiration: str = ""
    source: str = ""  # "profile", "env", "assume-role", "create-access-key", ...

    @property
    def name(self) -> str:
        """Short principal name - 'dev' from 'arn:aws:iam::111:user/dev'."""
        if not self.arn:
            return self.profile or "unknown"
        return self.arn.rsplit("/", 1)[-1]

    @property
    def has_keys(self) -> bool:
        return bool(self.access_key and self.secret_key)

    def to_env(self) -> dict:
        """Environment overlay for shelling out to `aws`/pacu/cloudfox."""
        env = dict(os.environ)
        if self.has_keys:
            env["AWS_ACCESS_KEY_ID"] = self.access_key
            env["AWS_SECRET_ACCESS_KEY"] = self.secret_key
            if self.session_token:
                env["AWS_SESSION_TOKEN"] = self.session_token
            else:
                env.pop("AWS_SESSION_TOKEN", None)
            env.pop("AWS_PROFILE", None)
        elif self.profile:
            env["AWS_PROFILE"] = self.profile
        if self.region:
            env["AWS_DEFAULT_REGION"] = self.region
            env["AWS_REGION"] = self.region
        return env

    def to_context(self) -> dict:
        """Placeholder values for command templates."""
        return {
            "PRINCIPAL_ARN": self.arn,
            "PRINCIPAL_NAME": self.name,
            "ACCOUNT_ID": self.account,
            "REGION": self.region,
            "PROFILE": self.profile,
            "AWS_ACCESS_KEY_ID": self.access_key,
            "AWS_SECRET_ACCESS_KEY": self.secret_key,
            "AWS_SESSION_TOKEN": self.session_token,
        }

    def to_dict(self, redact: bool = True) -> dict:
        d = asdict(self)
        if redact:
            d["secret_key"] = "***REDACTED***" if self.secret_key else ""
            d["session_token"] = "***REDACTED***" if self.session_token else ""
        return d


# ─── Rollback ledger ───────────────────────────────────────────────────────


@dataclass
class Mutation:
    """One state-changing API call, with everything needed to undo it.

    `awspwn pwn` refuses to run a mutating step whose undo cannot be recorded,
    unless --allow-orphan. `awspwn rollback` replays these LIFO.
    """

    ts: str
    api: str
    params: dict
    principal_used: str
    blast_radius: str
    undo_api: str = ""
    undo_params: dict = field(default_factory=dict)
    # Pre-change document for overwrite-style APIs (UpdateAssumeRolePolicy,
    # PutUserPolicy, UpdateFunctionCode) - restoring needs the original.
    original_state: Optional[dict] = None
    reverted: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Mutation":
        return cls(**d)


# ─── Findings / reporting (ADScout parity) ─────────────────────────────────


class Severity(IntEnum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


SEV_LABELS = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: " MED",
    Severity.LOW: " LOW",
    Severity.INFO: "INFO",
}


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    detail: str
    evidence: str = ""
    arn: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.name,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "arn": self.arn,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            severity=Severity[d.get("severity", "INFO")],
            category=d.get("category", ""),
            title=d.get("title", ""),
            detail=d.get("detail", ""),
            evidence=d.get("evidence", ""),
            arn=d.get("arn", ""),
        )
