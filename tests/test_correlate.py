"""Correlation-through-Grants correctness (Step 3, gap 2).

Correlation must evaluate a principal's structured grants against the ACTION-
SPECIFIC resource, honouring resource scoping and explicit denies - not read the
flat action_patterns list (which over-claims). Older graphs with only patterns
fall back to a resource-blind match, marked conditional.
"""

from awspwn.enum.correlate import (
    CORRELATION_VIA,
    correlate_resource_edges,
    reconcile_resource_edges,
)
from awspwn.enum.iam import Grants
from awspwn.models import Edge, Node, NodeKind


def _principal(arn, *docs, patterns=None):
    g = Grants()
    for d in docs:
        g.add_document(d)
    props = {}
    if docs:
        props["grant_statements"] = g.to_statements()
    if patterns is not None:
        props["action_patterns"] = patterns
    return Node(object_id=arn, name=arn.rsplit("/", 1)[-1], kind=NodeKind.IAM_ROLE, properties=props)


def _stmt(effect, **kw):
    s = {"Effect": effect}
    s.update(kw)
    return {"Statement": [s]}


def _secret(arn):
    return Node(object_id=arn, name=arn.rsplit(":", 1)[-1], kind=NodeKind.SECRET)


def _bucket(name):
    return Node(object_id=f"arn:aws:s3:::{name}", name=name, kind=NodeKind.S3_BUCKET)


def _edges(nodes):
    return {(e.source_id, e.target_id, e.kind): e for e in correlate_resource_edges(nodes, [])}


# ─── explicit deny is honoured (the reproduced over-claim) ───────────────────


def test_denied_secret_gets_no_edge():
    s_open = _secret("arn:aws:secretsmanager:us-east-1:111:secret:open")
    s_deny = _secret("arn:aws:secretsmanager:us-east-1:111:secret:locked")
    p = _principal(
        "arn:aws:iam::111:role/reader",
        _stmt("Allow", Action="secretsmanager:GetSecretValue", Resource="*"),
        _stmt("Deny", Action="secretsmanager:GetSecretValue", Resource=s_deny.object_id),
    )
    got = _edges([p, s_open, s_deny])
    assert (p.object_id, s_open.object_id, "GetSecretValue") in got      # allowed
    assert (p.object_id, s_deny.object_id, "GetSecretValue") not in got  # denied -> no edge


def test_scoped_allow_mints_only_the_in_scope_target():
    s_in = _secret("arn:aws:secretsmanager:us-east-1:111:secret:app-prod")
    s_out = _secret("arn:aws:secretsmanager:us-east-1:111:secret:other")
    p = _principal(
        "arn:aws:iam::111:role/reader",
        _stmt("Allow", Action="secretsmanager:GetSecretValue", Resource=s_in.object_id),
    )
    got = _edges([p, s_in, s_out])
    assert (p.object_id, s_in.object_id, "GetSecretValue") in got
    assert got[(p.object_id, s_in.object_id, "GetSecretValue")].conditional is False
    assert (p.object_id, s_out.object_id, "GetSecretValue") not in got


def test_conditional_allow_yields_conditional_edge():
    s = _secret("arn:aws:secretsmanager:us-east-1:111:secret:app")
    p = _principal(
        "arn:aws:iam::111:role/reader",
        _stmt("Allow", Action="secretsmanager:GetSecretValue", Resource="*",
              Condition={"StringEquals": {"aws:PrincipalTag/team": "sec"}}),
    )
    got = _edges([p, s])
    e = got[(p.object_id, s.object_id, "GetSecretValue")]
    assert e.conditional is True


# ─── action-specific resources (S3 object vs bucket) ─────────────────────────


def test_s3_action_specific_resources():
    b = _bucket("data-bucket")
    # GetObject is granted on bucket/* ; ListBucket is NOT (different resource).
    p = _principal(
        "arn:aws:iam::111:role/app",
        _stmt("Allow", Action="s3:GetObject", Resource=f"{b.object_id}/*"),
    )
    got = _edges([p, b])
    assert (p.object_id, b.object_id, "ReadS3Object") in got       # GetObject -> bucket/*
    assert (p.object_id, b.object_id, "ListS3Bucket") not in got   # ListBucket not granted


# ─── old-graph fallback (patterns only) is conditional ───────────────────────


def test_pattern_only_fallback_is_conditional():
    s = _secret("arn:aws:secretsmanager:us-east-1:111:secret:app")
    # No grant_statements - an older graph carrying only the display patterns.
    p = _principal("arn:aws:iam::111:role/legacy", patterns=["secretsmanager:GetSecretValue"])
    got = _edges([p, s])
    e = got[(p.object_id, s.object_id, "GetSecretValue")]
    assert e.conditional is True   # resource-blind -> may over-claim -> flagged


# ─── reconciliation delta (not add-only) ─────────────────────────────────────


SECRET = "arn:aws:secretsmanager:us-east-1:111:secret:app"


def _legacy_edge(src):
    return Edge(src, SECRET, "GetSecretValue", {"via": CORRELATION_VIA}, conditional=True)


def test_legacy_conditional_edge_removed_when_structured_deny_arrives():
    s = _secret(SECRET)
    p = _principal("arn:aws:iam::111:role/r",
                   _stmt("Deny", Action="secretsmanager:GetSecretValue", Resource=SECRET))
    legacy = _legacy_edge(p.object_id)
    upserts, removals = reconcile_resource_edges([p, s], [legacy])
    assert upserts == []
    assert (p.object_id, SECRET, "GetSecretValue") in removals


def test_legacy_conditional_edge_upgraded_when_structured_allow_confirms():
    s = _secret(SECRET)
    p = _principal("arn:aws:iam::111:role/r",
                   _stmt("Allow", Action="secretsmanager:GetSecretValue", Resource=SECRET))
    legacy = _legacy_edge(p.object_id)
    upserts, removals = reconcile_resource_edges([p, s], [legacy])
    assert removals == []
    up = {(e.source_id, e.target_id, e.kind): e for e in upserts}
    assert up[(p.object_id, SECRET, "GetSecretValue")].conditional is False  # upgraded


def test_empty_structured_grants_suppress_pattern_fallback_and_retract():
    s = _secret(SECRET)
    # grant_statements present but EMPTY -> authoritative "no permissions"; the
    # action_patterns must NOT be used, and a stale legacy edge is retracted.
    p = Node(object_id="arn:aws:iam::111:role/r", name="r", kind=NodeKind.IAM_ROLE,
             properties={"grant_statements": [], "action_patterns": ["secretsmanager:GetSecretValue"]})
    legacy = _legacy_edge(p.object_id)
    upserts, removals = reconcile_resource_edges([p, s], [legacy])
    assert upserts == []
    assert (p.object_id, SECRET, "GetSecretValue") in removals


def test_independent_provenance_edge_is_not_removed():
    s = _secret(SECRET)
    p = _principal("arn:aws:iam::111:role/r",
                   _stmt("Deny", Action="secretsmanager:GetSecretValue", Resource=SECRET))
    # Same kind, but NOT correlation-provenance -> preserved despite the deny.
    independent = Edge(p.object_id, SECRET, "GetSecretValue", {"via": "direct-observation"})
    upserts, removals = reconcile_resource_edges([p, s], [independent])
    assert removals == []


# ─── partial (non-authoritative) evidence: additive, never retracts ──────────


def _partial_principal(arn, *docs):
    g = Grants()
    for d in docs:
        g.add_document(d)
    return Node(object_id=arn, name=arn.rsplit("/", 1)[-1], kind=NodeKind.IAM_ROLE,
                properties={"grant_statements_partial": g.to_statements()})


def test_partial_grants_add_conditional_and_never_retract():
    s1 = _secret("arn:aws:secretsmanager:us-east-1:111:secret:one")
    s2 = _secret("arn:aws:secretsmanager:us-east-1:111:secret:two")
    p = _partial_principal("arn:aws:iam::111:role/r",
                           _stmt("Allow", Action="secretsmanager:GetSecretValue", Resource=s1.object_id))
    # An existing correlation edge to s2 that the partial view does not cover.
    prior = Edge(p.object_id, s2.object_id, "GetSecretValue", {"via": CORRELATION_VIA}, conditional=True)
    upserts, removals = reconcile_resource_edges([p, s1, s2], [prior])

    up = {(e.source_id, e.target_id, e.kind): e for e in upserts}
    # Adds a CONDITIONAL candidate for s1 (partial evidence is never confident)...
    assert up[(p.object_id, s1.object_id, "GetSecretValue")].conditional is True
    # ...and does NOT retract the s2 edge (a partial snapshot has no authority).
    assert removals == []


# ─── _star / ecr:GetAuthorizationToken has no resource scoping ────────────────


def _repo(arn):
    return Node(object_id=arn, name=arn.rsplit("/", 1)[-1], kind=NodeKind.ECR_REPOSITORY)


def test_ecr_get_auth_token_requires_star_resource():
    repo = _repo("arn:aws:ecr:us-east-1:111:repository/app")
    scoped = _principal(
        "arn:aws:iam::111:role/scoped",
        _stmt("Allow", Action="ecr:GetAuthorizationToken", Resource=repo.object_id),
        _stmt("Allow", Action="ecr:BatchGetImage", Resource=repo.object_id),
    )
    # GetAuthorizationToken has no resource-level scoping; a repo-scoped grant is
    # not a valid "*" grant, so the pull edge must not be minted.
    assert _edges([scoped, repo]) == {}

    ok = _principal(
        "arn:aws:iam::111:role/ok",
        _stmt("Allow", Action="ecr:GetAuthorizationToken", Resource="*"),
        _stmt("Allow", Action="ecr:BatchGetImage", Resource=repo.object_id),
    )
    got = _edges([ok, repo])
    assert (ok.object_id, repo.object_id, "ECRGetLoginPull") in got
