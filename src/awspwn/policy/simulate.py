"""Opportunistic edge refinement via iam:SimulatePrincipalPolicy.

AWS's own evaluator handles wildcards, NotAction/NotResource, explicit-deny
precedence, permission boundaries, SCPs, and most condition keys - things the
offline matcher in enum/iam.py cannot. When the caller holds
iam:SimulatePrincipalPolicy we use it to CONFIRM (clear `conditional`) or, on a
conclusive explicit deny, RETRACT an offline candidate edge from the current
vantage.

Three-valued by design - a non-allowed result is NOT collapsed to False:
  * ALLOWED       - EvalDecision "allowed" with no missing context.
  * EXPLICIT_DENY - EvalDecision "explicitDeny" with no missing context (the only
                    result conclusive enough to retract an edge).
  * INDETERMINATE - implicit deny (a resource-based policy we cannot see may still
                    grant it), missing condition context, or an unsupported combo.
  * UNAVAILABLE   - simulate could not be called at all (missing permission / API
                    error). The request itself is the availability probe; on
                    UNAVAILABLE the refiner stops rather than issuing a separate
                    redundant permission check.

Resource-policy caveat: SimulatePrincipalPolicy evaluates the IDENTITY policy
(with permission boundaries and SCPs) but does NOT retrieve resource policies, and
cannot simulate them for role targets. So an identity `allowed` is authoritative
only for identity-governed edges (IAM privesc); for resource access (S3, KMS,
Secrets Manager, Lambda, ...) and any sts:AssumeRole leg it is recorded as
evidence (`simulated_identity="allowed"`) but does NOT clear `conditional` - the
resource/trust policy could still deny. Explicit deny is conclusive for both.

Refinement is bounded by a per-pass unique-request budget (results deduplicated),
with conditional and privesc edges prioritized; truncation is logged.

moto does not implement SimulatePrincipalPolicy, so it returns UNAVAILABLE there
(and refinement is a no-op) - it is always opportunistic, never a dependency.
"""

from __future__ import annotations

from ..models import Edge

ALLOWED = "allowed"
EXPLICIT_DENY = "explicitDeny"
INDETERMINATE = "indeterminate"
UNAVAILABLE = "unavailable"
_BUDGET = "budget"  # internal: unique-request budget exhausted

# Max UNIQUE (principal, action, resource) simulations per refinement pass. AWS
# has no batch cost break here and a large resource inventory can otherwise fan
# out to thousands of sequential calls, so refinement is bounded and prioritized
# (conditional + privesc edges first). Deduplicated within a pass.
DEFAULT_SIM_BUDGET = 256


def simulate_action(client, principal_arn: str, action: str, resource: str = "*") -> str:
    """Three-valued (+UNAVAILABLE) outcome for ONE action against ONE resource.

    `principal_arn` must be the IAM principal ARN (never an STS session ARN); AWS
    rejects a session ARN as PolicySourceArn."""
    iam = client.client("iam")
    kwargs = {"PolicySourceArn": principal_arn, "ActionNames": [action]}
    if resource and resource != "*":
        kwargs["ResourceArns"] = [resource]
    try:
        resp = iam.simulate_principal_policy(**kwargs)
    except Exception:  # noqa: BLE001 - denied / unsupported / API error: cannot tell
        return UNAVAILABLE
    for res in resp.get("EvaluationResults", []):
        if res.get("EvalActionName") != action:
            continue
        if res.get("MissingContextValues"):
            return INDETERMINATE  # decision depended on context we did not supply
        decision = res.get("EvalDecision", "")
        if decision == "allowed":
            return ALLOWED
        if decision == "explicitDeny":
            return EXPLICIT_DENY
        return INDETERMINATE  # implicitDeny - a resource policy may still grant it
    return INDETERMINATE


# ─── edge-kind -> action legs (each with its ACTION-SPECIFIC resource) ────────


def _privesc_legs() -> dict:
    from ..enum.iam import _PRIVESC_RULES

    return {kind: required for kind, _sel, required in _PRIVESC_RULES}


def _resource_legs() -> dict:
    from ..enum.correlate import _RESOURCE_RULES

    return {edge_kind: action_res for _k, edge_kind, action_res in _RESOURCE_RULES}


def _tgt_resource(edge: Edge, dst, principal_arn: str) -> str:
    """The concrete resource a TGT-scoped privesc leg acts on. Some offline privesc
    edges point at the synthetic admin goal, carrying the real target in their
    properties (via_policy / via_group); others point straight at the target."""
    if edge.properties.get("via_policy"):
        return edge.properties["via_policy"]
    if edge.properties.get("via_group"):
        acct = principal_arn.split(":")[4] if principal_arn.count(":") >= 4 else ""
        return f"arn:aws:iam::{acct}:group/{edge.properties['via_group']}"
    return dst.object_id if dst is not None else "*"


def _resolve_legs(edge: Edge, principal_arn: str, dst):
    """(action, resource) legs to simulate for `edge`, or None if the edge is not
    simulate-refinable (identity/trust/structural edges are resource-policy or
    topology driven and are left alone)."""
    if edge.kind == "LambdaTakeover":
        fn = edge.properties.get("function_arn")
        if not fn:
            return None
        # All three against the specific function ARN. Left resource-gated (kept
        # conditional) - invoke/runtime/resource controls remain untested.
        return [("lambda:GetFunction", fn), ("lambda:UpdateFunctionCode", fn),
                ("lambda:InvokeFunction", fn)]
    priv = _privesc_legs()
    if edge.kind in priv:
        legs = []
        for action, role in priv[edge.kind]:
            if role == "SELF":
                r = principal_arn
            elif role == "TGT":
                r = _tgt_resource(edge, dst, principal_arn)
            else:  # ANY - gate/create action, resource out of scope
                r = "*"
            legs.append((action, r))
        return legs
    res = _resource_legs()
    if edge.kind in res:
        return [(action, res_fn(dst)) for action, res_fn in res[edge.kind]]
    return None


def _combine(client, principal_arn: str, legs, cache: dict, budget: int) -> str:
    """Composite outcome for an edge: each leg is simulated against its OWN
    resource (no resource cross-product). Results are cached by (action, resource)
    within the pass, so repeated gate actions (e.g. lambda:CreateFunction for many
    passable roles) are simulated once. Returns _BUDGET if a NEW unique request
    would exceed the pass budget. A conclusive deny on ANY required leg denies the
    composite; ALL allowed confirms it; anything else is indeterminate."""
    all_allowed = True
    for action, resource in legs:
        key = (action, resource)
        if key not in cache:
            if len(cache) >= budget:
                return _BUDGET
            cache[key] = simulate_action(client, principal_arn, action, resource)
        o = cache[key]
        if o == UNAVAILABLE:
            return UNAVAILABLE
        if o == EXPLICIT_DENY:
            return EXPLICIT_DENY
        if o != ALLOWED:
            all_allowed = False
    return ALLOWED if all_allowed else INDETERMINATE


def _identity_authorized(edge_kind: str, legs) -> bool:
    """True if the edge's authorization is governed purely by the IDENTITY policy
    (which SimulatePrincipalPolicy evaluates authoritatively, boundaries + SCPs
    included), so a clean allow may clear `conditional`.

    False for resource-policy-gated edges - S3/KMS/Secrets/Lambda resource access
    and any edge with an sts:AssumeRole leg (the role TRUST, a resource policy,
    is the real gate). Simulate does NOT retrieve resource policies (and cannot
    for role targets), so an identity allow there is NOT proof of live access."""
    if edge_kind not in _privesc_legs():
        return False  # correlate resource-access edge
    return not any(action == "sts:AssumeRole" for action, _r in legs)


def _independently_observed(edge: Edge) -> bool:
    """An edge backed by evidence other than the offline matcher / correlation is
    not retracted by a simulate deny (simulate evaluates identity policy only)."""
    return bool(edge.properties.get("observed")) or edge.properties.get("via") in (
        "trust-direct", "trust-account-root", "direct-observation",
    )


def _prioritize(edge_dst_pairs):
    priv = _privesc_legs()

    def key(item):
        edge, _dst = item
        return (not edge.conditional, edge.kind not in priv)  # conditional first, privesc first

    return sorted(edge_dst_pairs, key=key)


def refine_edges_with_simulation(client, principal_arn: str, edge_dst_pairs, log=None,
                                 budget: int = DEFAULT_SIM_BUDGET):
    """Refine the CURRENT vantage's outgoing edges with SimulatePrincipalPolicy.

    `edge_dst_pairs` is an iterable of (edge, dst_node) for edges whose source is
    the current vantage. Returns (upserts, removals):
      * upserts  - an edge whose IDENTITY simulation came back ALLOWED, re-emitted
        with a `simulated_identity="allowed"` evidence property (the existing `via`
        provenance preserved). `conditional` is cleared ONLY for identity-authorized
        edges; a resource-policy-gated edge keeps `conditional` because simulate did
        not (and cannot) evaluate the resource policy - the evidence is not proof of
        live access.
      * removals - (src, tgt, kind) of an offline candidate a conclusive
        EXPLICIT_DENY retracts (independently-observed edges preserved). An explicit
        identity deny overrides everything, so it is conclusive for both classes.
    Empty when simulation is unavailable. Bounded by `budget` unique requests
    (deduplicated), conditional/privesc edges prioritized. The caller applies the
    delta to BOTH the State ledger and the AttackGraph."""
    log = log or (lambda _m: None)
    upserts: list[Edge] = []
    removals: list[tuple[str, str, str]] = []
    cache: dict = {}
    refined = 0
    truncated = False
    for edge, dst in _prioritize(edge_dst_pairs):
        legs = _resolve_legs(edge, principal_arn, dst)
        if legs is None:
            continue
        outcome = _combine(client, principal_arn, legs, cache, budget)
        if outcome == UNAVAILABLE:
            break  # stop refining; keep any refinements already made
        if outcome == _BUDGET:
            truncated = True
            break
        refined += 1
        if outcome == ALLOWED:
            props = dict(edge.properties)
            props["simulated_identity"] = "allowed"  # identity-policy decision only
            new_conditional = False if _identity_authorized(edge.kind, legs) else edge.conditional
            upserts.append(Edge(edge.source_id, edge.target_id, edge.kind, props, conditional=new_conditional))
        elif outcome == EXPLICIT_DENY and not _independently_observed(edge):
            removals.append((edge.source_id, edge.target_id, edge.kind))
        # INDETERMINATE: leave the offline result as-is
    if refined:
        log(f"simulate refined {refined} edge(s): +{len(upserts)} confirmed, "
            f"-{len(removals)} retracted ({len(cache)} unique request(s))")
    if truncated:
        log(f"simulation budget ({budget}) reached - remaining edges left at offline fidelity")
    return upserts, removals
