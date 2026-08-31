"""Post-enumeration correlation - reconcile principal -> resource edges.

Enumerators run in parallel and are blind to each other, so resource-access
edges (a principal that can read a secret, scan a table, run a command on an
instance) cannot be minted inside any single enumerator. This pass runs after
the fan-out, evaluating each principal's permissions against the enumerated
resource nodes.

Authoritative input is the structured `grant_statements` persisted on a
principal node: correlation evaluates each rule through `Grants` with the
ACTION-SPECIFIC resource ARN (e.g. s3:GetObject against `bucket-arn/*`,
s3:ListBucket against the bucket ARN), so resource scoping, NotAction, Condition
keys, and explicit denies are all honoured. A principal explicitly denied a
secret does not gain a GetSecretValue edge to it.

Reconciliation, not add-only: because collection is incremental (structured
grants can arrive AFTER a legacy pattern-based edge), this returns a DELTA -
edges to upsert (new, or an existing correlation edge whose confidence improved)
and correlation edges to remove (no longer allowed). Only edges minted BY
correlation (`via == "correlation"`) are eligible for removal; edges backed by
independent provenance are preserved. The caller applies the delta to both the
State ledger and the live AttackGraph.

Three levels of authority drive whether a principal may RETRACT an edge:
  * `grant_statements` - AUTHORITATIVE (a complete policy read). May mint, upgrade,
    and RETRACT. An empty [] is authoritative "holds nothing" and retracts stale
    edges.
  * `grant_statements_partial` - non-authoritative evidence (an incomplete read).
    Mints CONDITIONAL candidates only; never retracts or replaces.
  * `action_patterns` only - the resource-blind legacy fallback; conditional,
    never retracts.
Only an authoritative-complete snapshot of a principal can remove that
principal's correlation edges, so an incomplete or legacy vantage can never erase
a prior complete snapshot's edges.
"""

from __future__ import annotations

import re

from ..models import Edge, Node, NodeKind
from .iam import Grants

CORRELATION_VIA = "correlation"


def _action_regex(pattern: str) -> re.Pattern:
    esc = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile("^" + esc + "$", re.IGNORECASE)


# ── Resource selectors: given a target resource node, the ARN to evaluate each
#    action against. node.object_id is the resource ARN for every resource kind
#    the enumerators emit.
def _self(n: Node) -> str:
    return n.object_id


def _bucket_arn(n: Node) -> str:
    return n.object_id if n.object_id.startswith("arn:") else f"arn:aws:s3:::{n.name or n.object_id}"


def _bucket_objects(n: Node) -> str:
    return _bucket_arn(n) + "/*"


def _star(_n: Node) -> str:
    # The concrete resource "*" - for actions with no resource-level scoping
    # (e.g. ecr:GetAuthorizationToken). Evaluated as allows_action(action, "*"),
    # so a grant scoped to a specific ARN does NOT satisfy it.
    return "*"


# (target NodeKind, edge kind, [(action, resource_selector), ...]).
_RESOURCE_RULES: list[tuple[NodeKind, str, list]] = [
    (NodeKind.SECRET, "GetSecretValue", [("secretsmanager:GetSecretValue", _self)]),
    (NodeKind.SSM_PARAMETER, "ReadSSMParameter", [("ssm:GetParameter", _self)]),
    (NodeKind.S3_BUCKET, "ReadS3Object", [("s3:GetObject", _bucket_objects)]),
    (NodeKind.S3_BUCKET, "ListS3Bucket", [("s3:ListBucket", _bucket_arn)]),
    (NodeKind.S3_BUCKET, "WriteS3Object", [("s3:PutObject", _bucket_objects)]),
    (NodeKind.DYNAMODB_TABLE, "DynamoDBScan", [("dynamodb:Scan", _self)]),
    (NodeKind.KMS_KEY, "KMSDecrypt", [("kms:Decrypt", _self)]),
    (NodeKind.EC2_INSTANCE, "SSMSendCommand", [("ssm:SendCommand", _self)]),
    (NodeKind.EC2_INSTANCE, "SSMStartSession", [("ssm:StartSession", _self)]),
    (NodeKind.LAMBDA_FUNCTION, "UpdateLambdaCode", [("lambda:UpdateFunctionCode", _self)]),
    (NodeKind.LAMBDA_FUNCTION, "InvokeLambda", [("lambda:InvokeFunction", _self)]),
    (NodeKind.CLOUDWATCH_LOG_GROUP, "ReadCloudWatchLogs", [("logs:FilterLogEvents", _self)]),
    # ecr:GetAuthorizationToken has no resource-level scoping (always "*");
    # ecr:BatchGetImage is scoped to the repository.
    (NodeKind.ECR_REPOSITORY, "ECRGetLoginPull",
     [("ecr:GetAuthorizationToken", _star), ("ecr:BatchGetImage", _self)]),
    (NodeKind.RDS_SNAPSHOT, "RestoreRDSFromSnapshot", [("rds:RestoreDBInstanceFromDBSnapshot", _self)]),
    (NodeKind.EBS_VOLUME, "CreateEBSSnapshot", [("ec2:CreateSnapshot", _self)]),
]

_CORRELATION_EDGE_KINDS = {edge_kind for _k, edge_kind, _ar in _RESOURCE_RULES} | {"LambdaTakeover"}

# Existing-Lambda takeover requires all three on the specific function ARN: read
# the current package (to back it up), overwrite it, and invoke it.
_TAKEOVER_ACTIONS = ["lambda:GetFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction"]


def _takeover_role(func: Node) -> str:
    """The function's CURRENT execution role (from its own props), or "" if it is
    not a takeover-eligible function. Container-image and non-Python-ZIP runtimes
    are excluded - the in-process strategy can only inject a compatible ZIP."""
    role_arn = func.properties.get("role_arn", "")
    if not role_arn or ":role/" not in role_arn:
        return ""
    if func.properties.get("package_type", "Zip") == "Image":
        return ""
    if not str(func.properties.get("runtime", "")).lower().startswith("python"):
        return ""
    return role_arn


def _allows_all(patterns: list[str], actions: list[str]) -> bool:
    compiled = [_action_regex(p) for p in patterns]
    for action in actions:
        if not any(rx.match(action) for rx in compiled):
            return False
    return True


def _decide(grants, patterns, action_res, target: Node):
    """(allowed, conditional) for one rule against `target`, or None if not
    allowed. Structured `grants` is resource-aware and authoritative (including an
    authoritative *empty* grant set); flat `patterns` is the resource-blind legacy
    fallback and always conditional."""
    if grants is not None:
        conditional = False
        for action, res_fn in action_res:
            ok, cond = grants.allows_action(action, res_fn(target))
            if not ok:
                return None
            conditional = conditional or cond
        return (True, conditional)
    if patterns and _allows_all(patterns, [a for a, _ in action_res]):
        return (True, True)
    return None


def _is_correlation_edge(e: Edge) -> bool:
    return e.properties.get("via") == CORRELATION_VIA


def reconcile_resource_edges(
    nodes: list[Node], edges: list[Edge]
) -> tuple[list[Edge], list[tuple[str, str, str]]]:
    """Reconcile correlation edges against current permissions.

    Returns (upserts, removals):
      * upserts - correlation edges that SHOULD exist (allowed), as new edges or
        as confidence upgrades for an existing correlation edge (add_edge only
        strengthens: conditional True->False).
      * removals - (source_id, target_id, kind) of correlation-provenance edges no
        longer allowed. Only `via == "correlation"` edges are removed; edges with
        independent provenance are preserved even if the rule no longer fires.
    """
    principals = [n for n in nodes if n.is_principal]
    resources_by_kind: dict[NodeKind, list[Node]] = {}
    for n in nodes:
        resources_by_kind.setdefault(n.kind, []).append(n)

    existing_by_key: dict[tuple[str, str, str], Edge] = {}
    for e in edges:
        existing_by_key.setdefault((e.source_id, e.target_id, e.kind), e)

    # Desired correlation edges (allowed), key -> conditional. `authoritative`
    # holds principals whose permission picture is COMPLETE (a full policy read);
    # only those may retract an edge. Partial reads and legacy patterns are
    # additive evidence: they can mint conditional candidates but never retract or
    # downgrade, so an incomplete vantage cannot erase a prior complete snapshot.
    desired: dict[tuple[str, str, str], bool] = {}
    authoritative: set[str] = set()
    for principal in principals:
        props = principal.properties
        # Authority is the snapshot status. `grant_statements` present without a
        # status is a legacy complete snapshot (back-compat with older graphs).
        if "grant_statements" in props and props.get("grant_read_status") != "partial":
            grants = Grants.from_statements(props.get("grant_statements") or [])
            patterns = None
            authoritative.add(principal.object_id)
        elif "grant_statements_partial" in props:
            grants = Grants.from_statements(props.get("grant_statements_partial") or [])
            patterns = None  # non-authoritative structured evidence
        else:
            grants = None
            patterns = props.get("action_patterns") or []
            if not patterns:
                continue
        is_auth = principal.object_id in authoritative
        for kind, edge_kind, action_res in _RESOURCE_RULES:
            for target in resources_by_kind.get(kind, []):
                decision = _decide(grants, patterns, action_res, target)
                if decision is None:
                    continue
                _allowed, conditional = decision
                # Non-authoritative evidence is always a conditional candidate.
                if not is_auth:
                    conditional = True
                desired[(principal.object_id, target.object_id, edge_kind)] = (conditional, {})

        # Lambda takeover: principal -> the function's CURRENT execution role,
        # derived from the function node's role_arn (never a stale structural edge),
        # so a role change reconciles the old takeover away.
        for func in resources_by_kind.get(NodeKind.LAMBDA_FUNCTION, []):
            role_arn = _takeover_role(func)
            if not role_arn:
                continue
            legs = [(action, _self) for action in _TAKEOVER_ACTIONS]
            decision = _decide(grants, patterns, legs, func)
            if decision is None:
                continue
            _allowed, conditional = decision
            if not is_auth:
                conditional = True
            extra = {
                "function_arn": func.object_id, "function_name": func.name,
                "region": func.region, "runtime": func.properties.get("runtime", ""),
                "handler": func.properties.get("handler", ""),
                "package_type": func.properties.get("package_type", "Zip"),
                "role_arn": role_arn,
            }
            desired[(principal.object_id, role_arn, "LambdaTakeover")] = (conditional, extra)

    upserts: list[Edge] = []
    for key, (conditional, extra) in desired.items():
        src, tgt, kind = key
        props = {"via": CORRELATION_VIA, **extra}
        prev = existing_by_key.get(key)
        if prev is None:
            upserts.append(Edge(src, tgt, kind, props, conditional=conditional))
        elif _is_correlation_edge(prev) and (extra or (prev.conditional and not conditional)):
            # Re-emit to refresh metadata (e.g. a changed function handler) and/or
            # improve confidence (legacy/partial conditional -> confirmed).
            upserts.append(Edge(src, tgt, kind, props, conditional=conditional))

    removals: list[tuple[str, str, str]] = []
    for key, e in existing_by_key.items():
        if key in desired:
            continue
        if key[0] not in authoritative:
            continue  # only a complete snapshot of the source principal may retract
        if e.kind in _CORRELATION_EDGE_KINDS and _is_correlation_edge(e):
            removals.append(key)
    return upserts, removals


def correlate_resource_edges(nodes: list[Node], edges: list[Edge]) -> list[Edge]:
    """Back-compat convenience for the fresh-collection case: the upsert half of
    reconciliation. Callers that maintain a live graph across collections should
    use reconcile_resource_edges and also apply the removals."""
    upserts, _removals = reconcile_resource_edges(nodes, edges)
    return upserts
