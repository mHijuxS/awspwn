"""Foundation for incremental `roam` collection (Steps 1-2).

Covers the load-bearing pieces the pivot loop rests on, mostly without AWS:
  * canonical STS assumed-role -> IAM role ARN normalization;
  * merge semantics with property/`conditional` enrichment on the graph AND state,
    plus dedup and adjacency-consistent removal;
  * union correlation (new principal x old resource, and vice versa);
  * (moto) collect_from being account-additive - a cross-account collection grows
    one graph instead of resetting it - and findings/denials surviving repeated
    collections without unbounded growth.
"""

import argparse

import pytest

from awspwn.aws_client import canonical_principal_id
from awspwn.enum.correlate import correlate_resource_edges
from awspwn.graph import AttackGraph
from awspwn.models import AwsIdentity, Edge, Finding, Node, NodeKind, Severity
from awspwn.state import State


# ─── canonical principal identity ────────────────────────────────────────────


def test_canonical_id_normalizes_assumed_role():
    ident = AwsIdentity(arn="arn:aws:sts::111111111111:assumed-role/app-role/awspwn-sess")
    assert canonical_principal_id(ident) == "arn:aws:iam::111111111111:role/app-role"


def test_canonical_id_passthrough_for_iam_and_bare_arns():
    # IAM user / role ARNs and non-STS strings are returned unchanged.
    assert (
        canonical_principal_id(AwsIdentity(arn="arn:aws:iam::1:user/dev"))
        == "arn:aws:iam::1:user/dev"
    )
    assert (
        canonical_principal_id(AwsIdentity(arn="arn:aws:iam::1:role/app-role"))
        == "arn:aws:iam::1:role/app-role"
    )
    # STS federated-user has no IAM role node - pass through, do not fabricate one.
    fed = "arn:aws:sts::1:federated-user/bob"
    assert canonical_principal_id(AwsIdentity(arn=fed)) == fed
    # Accepts a bare string too.
    assert canonical_principal_id("not-an-arn") == "not-an-arn"


# ─── graph merge semantics ───────────────────────────────────────────────────


def test_graph_add_node_enriches_instead_of_discarding():
    # A role first seen as a bare ARN (e.g. a Lambda's execution role), later
    # enriched with its policies. setdefault would keep the empty first copy.
    graph = AttackGraph({}, [])
    graph.add_node(Node(object_id="arn:role/app", kind=NodeKind.UNKNOWN))
    graph.add_node(Node(
        object_id="arn:role/app", name="app", kind=NodeKind.IAM_ROLE,
        account="111", properties={"reachable_via": "lambda", "tag": "prod"},
    ))
    n = graph.nodes["arn:role/app"]
    assert n.name == "app"
    assert n.kind == NodeKind.IAM_ROLE            # UNKNOWN upgraded
    assert n.account == "111"
    assert n.properties["reachable_via"] == "lambda"   # non-grant props merge
    assert n.properties["tag"] == "prod"


def test_graph_add_edge_dedups_and_enriches_conditional():
    graph = AttackGraph({}, [])
    graph.add_edge(Edge("a", "b", "CanAssume", {"via": "trust"}, conditional=True))
    # Re-add the same edge, now CONFIRMED and with extra properties.
    graph.add_edge(Edge("a", "b", "CanAssume", {"src": "simulate"}, conditional=False))
    assert len(graph.edges) == 1                  # deduped
    assert len(graph.outgoing_edges("a")) == 1    # adjacency not duplicated
    assert len(graph.incoming_edges("b")) == 1
    e = graph.edges[0]
    assert e.conditional is False                 # True -> False upgrade
    assert e.properties == {"via": "trust", "src": "simulate"}
    # Confidence is never lost: a later conditional copy cannot re-flag it.
    graph.add_edge(Edge("a", "b", "CanAssume", {}, conditional=True))
    assert graph.edges[0].conditional is False


def test_graph_owns_edge_list_no_aliasing_double_append():
    # Regression: AttackGraph must copy the edge list, not alias state.edges.
    # collect_from merges into both stores in lockstep; an alias made
    # state.add_edge mutate the graph's list behind its adjacency index, so the
    # subsequent graph.add_edge double-appended (2 persisted edges, 1 adjacency).
    state = State()
    state.add_edge(Edge("a", "b", "CanAssume"))
    graph = AttackGraph(state.node_map(), state.edges)
    assert graph.edges is not state.edges                 # not aliased

    e2 = Edge("a", "c", "GetSecretValue")
    state.add_edge(e2)
    graph.add_edge(e2)
    assert len(state.edges) == 2
    assert len(graph.edges) == 2                           # NOT 3
    assert len(graph.outgoing_edges("a")) == 2             # one per edge, no dup


def test_graph_remove_edge_clears_both_adjacency_indexes():
    graph = AttackGraph({}, [])
    graph.add_edge(Edge("a", "b", "CanAssume"))
    graph.add_edge(Edge("a", "c", "GetSecretValue"))
    assert graph.remove_edge("a", "b", "CanAssume") is True
    assert all(e.target_id != "b" for e in graph.outgoing_edges("a"))
    assert graph.incoming_edges("b") == []
    assert len(graph.edges) == 1                  # the a->c edge survives
    assert graph.remove_edge("a", "b", "CanAssume") is False  # idempotent


def test_state_add_edge_enriches_not_drops():
    state = State()
    state.add_edge(Edge("a", "b", "AttachRolePolicy", {"n": 1}, conditional=True))
    state.add_edge(Edge("a", "b", "AttachRolePolicy", {"m": 2}, conditional=False))
    assert len(state.edges) == 1
    e = state.edges[0]
    assert e.conditional is False
    assert e.properties == {"n": 1, "m": 2}


def test_state_add_finding_dedups_by_identity():
    state = State()
    f = Finding(Severity.INFO, "enum", "AccessDenied: iam:ListUsers", "", arn="arn:role/a")
    state.add_finding(f)
    state.add_finding(Finding(Severity.INFO, "enum", "AccessDenied: iam:ListUsers", "", arn="arn:role/a"))
    assert len(state.findings) == 1               # same vantage -> deduped
    # Same denial from a DIFFERENT vantage is distinct intel - kept.
    state.add_finding(Finding(Severity.INFO, "enum", "AccessDenied: iam:ListUsers", "", arn="arn:role/b"))
    assert len(state.findings) == 2


def test_state_add_node_enriches_and_survives_roundtrip():
    # State node merge must mirror the graph's: enrich region + upgrade UNKNOWN
    # kind, and persist through save/load (not just in the live graph).
    from awspwn.state import State as _State

    state = State()
    state.add_node(Node(object_id="arn:res/x", kind=NodeKind.UNKNOWN))
    state.add_node(Node(object_id="arn:res/x", name="x", kind=NodeKind.SECRET,
                        account="111", region="eu-west-1",
                        properties={"tag": "prod"}))
    reloaded = _State.from_dict(state.to_dict())
    n = reloaded.node_map()["arn:res/x"]
    assert n.kind == NodeKind.SECRET       # UNKNOWN upgraded
    assert n.region == "eu-west-1"         # region copied (was the gap vs graph)
    assert n.account == "111"
    assert n.properties == {"tag": "prod"}


# ─── authority-aware permission-snapshot merge ───────────────────────────────

ROLE = "arn:aws:iam::111:role/app"


def _complete(**extra):
    props = {
        "grant_read_status": "complete",
        "grant_statements": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}],
        "attached_policies": ["arn:aws:iam::111:policy/Cust"],
        "action_patterns": ["secretsmanager:GetSecretValue"],
        "is_admin": False,
    }
    props.update(extra)
    return Node(object_id=ROLE, name="app", kind=NodeKind.IAM_ROLE, properties=props)


def _partial(**extra):
    props = {
        "grant_read_status": "partial",
        "grant_statements_partial": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        "attached_policies_partial": [],
        "action_patterns_partial": ["s3:GetObject"],
    }
    props.update(extra)
    return Node(object_id=ROLE, name="app", kind=NodeKind.IAM_ROLE, properties=props)


def test_partial_merge_does_not_corrupt_complete_snapshot():
    # The reproduced bug: a later partial read must not leave both keys, overwrite
    # authoritative display data, or strand a stale is_admin.
    state = State()
    state.add_node(_complete())
    state.add_node(_partial())
    p = state.node_map()[ROLE].properties
    assert p["grant_read_status"] == "complete"                 # NOT downgraded
    assert "grant_statements" in p
    assert p["attached_policies"] == ["arn:aws:iam::111:policy/Cust"]  # not overwritten
    assert p["action_patterns"] == ["secretsmanager:GetSecretValue"]
    assert p["is_admin"] is False                               # consistent, not stale
    assert "grant_statements_partial" not in p                  # partial evidence dropped
    assert "action_patterns_partial" not in p


def test_complete_supersedes_and_clears_partial():
    state = State()
    state.add_node(_partial())
    state.add_node(_complete(is_admin=True))
    p = state.node_map()[ROLE].properties
    assert p["grant_read_status"] == "complete"
    assert p["is_admin"] is True
    assert "grant_statements_partial" not in p                  # cleared by the complete read
    assert "action_patterns_partial" not in p


def test_none_read_preserves_prior_complete():
    state = State()
    state.add_node(_complete(is_admin=True))
    # A denied self-read: only confirmed_actions, no grant status.
    state.add_node(Node(object_id=ROLE, name="app", kind=NodeKind.IAM_ROLE,
                        properties={"is_caller": True, "confirmed_actions": ["sts:GetCallerIdentity"]}))
    p = state.node_map()[ROLE].properties
    assert "grant_statements" in p                              # prior knowledge preserved
    assert p["is_admin"] is True
    assert p["confirmed_actions"] == ["sts:GetCallerIdentity"]  # non-grant key still merges


def test_merged_complete_node_stays_authoritative_for_reconcile():
    # After a partial merge attempt, the principal is still authoritative: an
    # explicit deny in its complete grant_statements retracts a stale edge.
    from awspwn.enum.correlate import reconcile_resource_edges

    secret = "arn:aws:secretsmanager:us-east-1:111:secret:x"
    state = State()
    state.add_node(_complete(grant_statements=[
        {"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": secret}]))
    state.add_node(_partial())  # partial cannot strip authority
    state.add_node(Node(object_id=secret, name="x", kind=NodeKind.SECRET))
    stale = Edge(ROLE, secret, "GetSecretValue", {"via": "correlation"}, conditional=True)
    _upserts, removals = reconcile_resource_edges(state.nodes, [stale])
    assert (ROLE, secret, "GetSecretValue") in removals


# ─── canonical caller wiring ─────────────────────────────────────────────────


class _StubClient:
    def __init__(self, arn, account):
        self.identity = AwsIdentity(arn=arn, account=account, region="us-east-1")


def test_reset_helper_persists_canonical_caller_arn():
    from awspwn.cli import _reset_state_if_foreign_account

    client = _StubClient("arn:aws:sts::111:assumed-role/app-role/sess", "111")
    state = _reset_state_if_foreign_account(State(), client)
    # caller_arn must be the IAM role node id, not the STS session ARN, so
    # analyze/path can resolve the source node.
    assert state.caller_arn == "arn:aws:iam::111:role/app-role"
    assert state.origin_account == "111"


def test_sts_node_keyed_by_iam_arn_with_session_evidence():
    from awspwn.enum.sts import StsEnumerator

    class _FakeSvc:
        def get_caller_identity(self):
            return {"Arn": "arn:aws:sts::111:assumed-role/app-role/sess",
                    "Account": "111", "UserId": "AROAX:sess"}

        def get_role(self, **_kw):  # no path resolution available in this stub
            raise RuntimeError("denied")

    class _FakeClient:
        def __init__(self):
            self.identity = AwsIdentity(region="us-east-1")

        def client(self, _svc, region=None):
            return _FakeSvc()

    result = StsEnumerator().enumerate(_FakeClient(), "us-east-1")
    node = result.nodes[0]
    assert node.object_id == "arn:aws:iam::111:role/app-role"   # canonical key
    assert node.kind == NodeKind.IAM_ROLE
    assert node.properties["session_arn"] == "arn:aws:sts::111:assumed-role/app-role/sess"


# ─── union correlation ───────────────────────────────────────────────────────


def _principal(arn, patterns):
    return Node(object_id=arn, name=arn.rsplit("/", 1)[-1], kind=NodeKind.IAM_ROLE,
                properties={"action_patterns": patterns})


def _secret(arn):
    return Node(object_id=arn, name=arn.rsplit(":", 1)[-1], kind=NodeKind.SECRET)


def test_correlation_is_union_over_merged_graph():
    # Principal A (secrets reader) + one secret discovered first.
    a = _principal("arn:role/a", ["secretsmanager:GetSecretValue"])
    s1 = _secret("arn:secret:one")
    nodes = [a, s1]
    edges = correlate_resource_edges(nodes, [])
    assert {(e.source_id, e.target_id, e.kind) for e in edges} == {
        ("arn:role/a", "arn:secret:one", "GetSecretValue")
    }

    # A NEW principal B appears (old resource) AND a NEW secret appears (old
    # principal). Re-running correlation over the whole merged node set must mint
    # BOTH: B->one and A->two. Passing the existing edge dedups A->one out.
    b = _principal("arn:role/b", ["secretsmanager:GetSecretValue"])
    s2 = _secret("arn:secret:two")
    merged_nodes = nodes + [b, s2]
    new_edges = correlate_resource_edges(merged_nodes, list(edges))
    got = {(e.source_id, e.target_id, e.kind) for e in new_edges}
    assert ("arn:role/b", "arn:secret:one", "GetSecretValue") in got   # new prin x old res
    assert ("arn:role/a", "arn:secret:two", "GetSecretValue") in got   # old prin x new res
    assert ("arn:role/a", "arn:secret:one", "GetSecretValue") not in got  # deduped


# ─── collect_from: account-additive + accumulation (moto) ───────────────────


moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402
import boto3  # noqa: E402

from awspwn.aws_client import AwsClient  # noqa: E402
from awspwn.cli import collect_from  # noqa: E402


def _args(tmp_path):
    return argparse.Namespace(
        loot_dir=str(tmp_path), region="us-east-1", verbose=False,
    )


def _live_client():
    c = AwsClient(AwsIdentity(access_key="testing", secret_key="testing",
                              region="us-east-1", source="test"))
    c.whoami()
    return c


@mock_aws
def test_collect_from_is_account_additive_no_reset(tmp_path):
    boto3.client("iam", region_name="us-east-1").create_user(UserName="dev")
    client = _live_client()
    acct = client.identity.account

    # An engagement that started in a DIFFERENT account, with a pre-existing node
    # from that account already in the graph.
    state = State(origin_account="999999999999")
    state.add_node(Node(object_id="arn:aws:iam::999999999999:role/prior",
                        name="prior", kind=NodeKind.IAM_ROLE, account="999999999999"))
    graph = AttackGraph(state.node_map(), state.edges)

    collect_from(client, state, graph, _args(tmp_path), phase2=False)

    ids = {n.object_id for n in state.nodes}
    assert "arn:aws:iam::999999999999:role/prior" in ids       # prior account NOT wiped
    assert any(acct in i and "user/dev" in i for i in ids)      # new account merged in
    assert state.origin_account == "999999999999"              # origin unchanged


@mock_aws
def test_collect_from_reconciles_stale_correlation_edge_in_both_stores(tmp_path):
    # A stale legacy correlation edge (conditional, pattern-based) exists; the
    # principal's structured grants now explicitly DENY the secret. collect_from's
    # reconciliation must retract the edge from BOTH state and the live graph.
    from awspwn.enum.iam import Grants

    boto3.client("iam", region_name="us-east-1").create_user(UserName="dev")
    client = _live_client()

    secret_arn = "arn:aws:secretsmanager:us-east-1:111:secret:app"
    role_arn = "arn:aws:iam::111:role/reader"
    g = Grants()
    g.add_document({"Statement": [{"Effect": "Deny",
                                   "Action": "secretsmanager:GetSecretValue",
                                   "Resource": secret_arn}]})

    state = State()
    state.add_node(Node(object_id=secret_arn, name="app", kind=NodeKind.SECRET, account="111"))
    state.add_node(Node(object_id=role_arn, name="reader", kind=NodeKind.IAM_ROLE, account="111",
                        properties={"grant_statements": g.to_statements()}))
    state.add_edge(Edge(role_arn, secret_arn, "GetSecretValue",
                        {"via": "correlation"}, conditional=True))
    graph = AttackGraph(state.node_map(), state.edges)
    key = (role_arn, secret_arn, "GetSecretValue")
    assert any((e.source_id, e.target_id, e.kind) == key for e in graph.edges)

    collect_from(client, state, graph, _args(tmp_path), phase2=False)

    assert not any((e.source_id, e.target_id, e.kind) == key for e in state.edges)
    assert not any((e.source_id, e.target_id, e.kind) == key for e in graph.edges)
    assert graph.outgoing_edges(role_arn) == []  # adjacency index cleared too


@mock_aws
def test_findings_and_denials_survive_repeated_collection(tmp_path):
    boto3.client("iam", region_name="us-east-1").create_user(UserName="dev")
    client = _live_client()
    state = State()
    graph = AttackGraph(state.node_map(), state.edges)
    args = _args(tmp_path)

    collect_from(client, state, graph, args, phase2=False)
    f1, d1, n1 = len(state.findings), len(state.denied), len(state.nodes)
    collect_from(client, state, graph, args, phase2=False)

    # Identical second pass from the same vantage must not grow findings/denials
    # (dedup) nor duplicate nodes.
    assert len(state.findings) == f1
    assert len(state.denied) == d1
    assert len(state.nodes) == n1
    # Denials are unique action strings.
    assert len(state.denied) == len(set(state.denied))
