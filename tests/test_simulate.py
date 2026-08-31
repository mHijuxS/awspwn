"""SimulatePrincipalPolicy refinement (Step 5).

Offline unit tests with a stubbed simulate_principal_policy - moto does not
implement it. Cover the three-valued outcomes, action-specific composite
resources (no cross-product), PolicySourceArn use, confirm/retract/leave, and
provenance preservation.
"""

from awspwn.graph import AttackGraph
from awspwn.models import Edge, Node, NodeKind
from awspwn.policy.simulate import (
    ALLOWED,
    EXPLICIT_DENY,
    INDETERMINATE,
    UNAVAILABLE,
    refine_edges_with_simulation,
    simulate_action,
)
from awspwn.state import State


class _FakeIam:
    def __init__(self, responder, calls):
        self._responder = responder
        self.calls = calls

    def simulate_principal_policy(self, **kwargs):
        self.calls.append(kwargs)
        return self._responder(kwargs)


class _FakeClient:
    """Only exposes simulate_principal_policy - any separate permission probe
    would AttributeError, proving availability is checked via the request itself."""

    def __init__(self, responder, arn="arn:aws:iam::111:role/app"):
        self.calls = []
        self._iam = _FakeIam(responder, self.calls)

        class _Ident:
            pass
        self.identity = _Ident()
        self.identity.arn = arn

    def client(self, _svc, region=None):
        return self._iam


def _responder(decisions, missing=(), raise_on=()):
    def r(kwargs):
        action = kwargs["ActionNames"][0]
        if action in raise_on:
            raise RuntimeError("boom")
        d = decisions.get(action, "implicitDeny")
        res = {"EvalActionName": action, "EvalDecision": d}
        if action in missing:
            res["MissingContextValues"] = ["aws:MultiFactorAuthPresent"]
        return {"EvaluationResults": [res]}
    return r


ARN = "arn:aws:iam::111:role/app"


# ─── three-valued outcomes (never collapse to False) ─────────────────────────


def test_simulate_action_three_outcomes():
    assert simulate_action(_FakeClient(_responder({"a": "allowed"})), ARN, "a") == ALLOWED
    assert simulate_action(_FakeClient(_responder({"a": "explicitDeny"})), ARN, "a") == EXPLICIT_DENY
    assert simulate_action(_FakeClient(_responder({"a": "implicitDeny"})), ARN, "a") == INDETERMINATE


def test_missing_context_is_indeterminate_not_allowed():
    c = _FakeClient(_responder({"a": "allowed"}, missing=("a",)))
    assert simulate_action(c, ARN, "a") == INDETERMINATE


def test_api_failure_is_unavailable():
    c = _FakeClient(_responder({}, raise_on=("a",)))
    assert simulate_action(c, ARN, "a") == UNAVAILABLE


def test_policy_source_arn_is_the_principal():
    c = _FakeClient(_responder({"a": "allowed"}))
    simulate_action(c, ARN, "secretsmanager:GetSecretValue", "arn:aws:secretsmanager:us-east-1:111:secret:x")
    assert c.calls[0]["PolicySourceArn"] == ARN
    assert c.calls[0]["ResourceArns"] == ["arn:aws:secretsmanager:us-east-1:111:secret:x"]


# ─── composite: action-specific resources, no cross-product ──────────────────


def test_composite_legs_use_action_specific_resources():
    role = Node("arn:aws:iam::111:role/target", "target", NodeKind.IAM_ROLE)
    edge = Edge(ARN, role.object_id, "CreateLambdaWithRole", {})
    c = _FakeClient(_responder({
        "iam:PassRole": "allowed", "lambda:CreateFunction": "allowed", "lambda:InvokeFunction": "allowed"}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, role)])
    # One call per leg (no action×resource cross-product batch).
    by_action = {call["ActionNames"][0]: call for call in c.calls}
    assert by_action["iam:PassRole"]["ResourceArns"] == [role.object_id]   # TGT -> role
    assert "ResourceArns" not in by_action["lambda:CreateFunction"]         # ANY -> "*"
    assert "ResourceArns" not in by_action["lambda:InvokeFunction"]
    assert len(c.calls) == 3
    assert len(up) == 1 and rm == []


# ─── confirm / retract / leave ───────────────────────────────────────────────


def _secret(arn="arn:aws:secretsmanager:us-east-1:111:secret:x"):
    return Node(arn, "x", NodeKind.SECRET)


def _admin_goal():
    return Node("awspwn:admin:111", "admin", NodeKind.AWS_ACCOUNT, properties={"synthetic_goal": True})


def test_identity_edge_allow_clears_conditional_keeps_via():
    # AttachUserPolicy is identity-policy governed -> a clean allow may clear.
    goal = _admin_goal()
    edge = Edge(ARN, goal.object_id, "AttachUserPolicy", {}, conditional=True)
    c = _FakeClient(_responder({"iam:AttachUserPolicy": "allowed"}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, goal)])
    assert rm == []
    e = up[0]
    assert e.conditional is False                        # confirmed via identity policy
    assert e.properties["simulated_identity"] == "allowed"


def test_resource_edge_allow_keeps_conditional_records_evidence():
    # Simulate does not evaluate the resource policy, so an identity allow on a
    # resource-access edge is EVIDENCE, not proof: conditional is retained.
    s = _secret()
    edge = Edge(ARN, s.object_id, "GetSecretValue", {"via": "correlation"}, conditional=True)
    c = _FakeClient(_responder({"secretsmanager:GetSecretValue": "allowed"}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, s)])
    assert rm == []
    e = up[0]
    assert e.conditional is True                         # NOT cleared - resource policy unknown
    assert e.properties["via"] == "correlation"          # provenance preserved
    assert e.properties["simulated_identity"] == "allowed"
    assert "simulated" not in e.properties               # never the "proven access" key


def test_assume_role_leg_keeps_conditional():
    # AttachRolePolicy requires sts:AssumeRole (trust-gated) -> keep conditional.
    role = Node("arn:aws:iam::111:role/target", "target", NodeKind.IAM_ROLE)
    edge = Edge(ARN, role.object_id, "AttachRolePolicy", {}, conditional=True)
    c = _FakeClient(_responder({"iam:AttachRolePolicy": "allowed", "sts:AssumeRole": "allowed"}))
    up, _rm = refine_edges_with_simulation(c, ARN, [(edge, role)])
    assert up[0].conditional is True


def test_explicit_deny_retracts_offline_candidate():
    s = _secret()
    edge = Edge(ARN, s.object_id, "GetSecretValue", {"via": "correlation"}, conditional=True)
    c = _FakeClient(_responder({"secretsmanager:GetSecretValue": "explicitDeny"}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, s)])
    assert up == []
    assert rm == [(ARN, s.object_id, "GetSecretValue")]


def test_implicit_deny_leaves_edge_untouched():
    s = _secret()
    edge = Edge(ARN, s.object_id, "GetSecretValue", {"via": "correlation"}, conditional=True)
    c = _FakeClient(_responder({"secretsmanager:GetSecretValue": "implicitDeny"}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, s)])
    assert up == [] and rm == []               # indeterminate: leave the offline result


def test_independently_observed_edge_not_retracted():
    s = _secret()
    edge = Edge(ARN, s.object_id, "GetSecretValue", {"via": "correlation", "observed": True}, conditional=True)
    c = _FakeClient(_responder({"secretsmanager:GetSecretValue": "explicitDeny"}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, s)])
    assert rm == []                            # provenance preserved despite deny


def test_unavailable_makes_refinement_a_noop():
    s = _secret()
    edge = Edge(ARN, s.object_id, "GetSecretValue", {"via": "correlation"}, conditional=True)
    c = _FakeClient(_responder({}, raise_on=("secretsmanager:GetSecretValue",)))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, s)])
    assert up == [] and rm == []


def test_non_refinable_edges_are_skipped_without_calls():
    role = Node("arn:aws:iam::111:role/r", "r", NodeKind.IAM_ROLE)
    edge = Edge(ARN, role.object_id, "CanAssume", {"via": "trust-direct"})  # trust-driven, not refinable
    c = _FakeClient(_responder({}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, role)])
    assert up == [] and rm == [] and c.calls == []


# ─── dedup + budget ──────────────────────────────────────────────────────────


def test_repeated_gate_actions_deduplicated():
    # Two passable edges to different roles share the lambda gate actions ("*")
    # which must be simulated ONCE, not per role.
    r1 = Node("arn:aws:iam::111:role/a", "a", NodeKind.IAM_ROLE)
    r2 = Node("arn:aws:iam::111:role/b", "b", NodeKind.IAM_ROLE)
    e1 = Edge(ARN, r1.object_id, "CreateLambdaWithRole", {})
    e2 = Edge(ARN, r2.object_id, "CreateLambdaWithRole", {})
    c = _FakeClient(_responder({
        "iam:PassRole": "allowed", "lambda:CreateFunction": "allowed", "lambda:InvokeFunction": "allowed"}))
    refine_edges_with_simulation(c, ARN, [(e1, r1), (e2, r2)])
    actions = [call["ActionNames"][0] for call in c.calls]
    # PassRole differs by role (2), the two gate actions are shared ("*") -> 1 each.
    assert actions.count("lambda:CreateFunction") == 1
    assert actions.count("lambda:InvokeFunction") == 1
    assert actions.count("iam:PassRole") == 2


def test_budget_truncates_and_logs():
    secrets = [Node(f"arn:aws:secretsmanager:us-east-1:111:secret:{i}", str(i), NodeKind.SECRET) for i in range(5)]
    edges = [(Edge(ARN, s.object_id, "GetSecretValue", {"via": "correlation"}, conditional=True), s) for s in secrets]
    c = _FakeClient(_responder({"secretsmanager:GetSecretValue": "allowed"}))
    logs = []
    refine_edges_with_simulation(c, ARN, edges, log=logs.append, budget=2)
    assert len(c.calls) == 2                              # bounded at the budget
    assert any("budget" in m.lower() for m in logs)


# ─── the delta applies to State AND AttackGraph together ─────────────────────


def test_delta_applies_to_both_stores():
    goal = _admin_goal()
    edge = Edge(ARN, goal.object_id, "AttachUserPolicy", {}, conditional=True)
    state = State()
    state.add_node(Node(ARN, "app", NodeKind.IAM_ROLE))
    state.add_node(goal)
    state.add_edge(edge)
    graph = AttackGraph(state.node_map(), state.edges)

    c = _FakeClient(_responder({"iam:AttachUserPolicy": "allowed"}))
    up, rm = refine_edges_with_simulation(c, ARN, [(edge, goal)])
    for e in up:
        state.add_edge(e)
        graph.add_edge(e)
    for src, tgt, kind in rm:
        state.remove_edge(src, tgt, kind)
        graph.remove_edge(src, tgt, kind)

    assert state.edges[0].conditional is False
    assert graph.outgoing_edges(ARN)[0].conditional is False
    assert graph.edges[0].properties["simulated_identity"] == "allowed"
