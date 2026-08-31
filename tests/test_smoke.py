"""Offline smoke tests - no AWS, no network. Exercise models / graph / abuse /
edge DB / pathfinding on the committed fixture graph.
"""

import os

from awspwn.abuse import (
    edges_by_category,
    format_command,
    get_abuse_info,
    list_abusable_edges,
)
from awspwn.graph import AttackGraph, _edge_cost
from awspwn.models import BlastRadius, NodeKind
from awspwn.state import load_graph

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_graph.json")


def test_edge_db_populated():
    edges = list_abusable_edges()
    assert len(edges) >= 50
    cats = edges_by_category()
    for c in ("iam", "compute", "data", "persist", "org"):
        assert cats.get(c), f"category {c} empty"


def test_every_abusable_edge_has_steps_and_blast():
    for kind in list_abusable_edges():
        info = get_abuse_info(kind)
        assert info is not None
        assert info.linux_steps, f"{kind} has no steps"
        assert isinstance(info.blast_radius, BlastRadius)


def test_format_command_preserves_json_braces():
    cmd = "aws iam put-user-policy --policy-document '{\"Version\":\"2012-10-17\"}' --user {TARGET_NAME}"
    out = format_command(cmd, {"TARGET_NAME": "dev"})
    assert '{"Version":"2012-10-17"}' in out
    assert "--user dev" in out


def test_blast_surcharge_orders_edges():
    # A read identity gain must be cheaper than an external-exposure edge.
    assert _edge_cost("CanAssume") < _edge_cost("ShareEBSSnapshot")
    assert _edge_cost("GetSecretValue") <= _edge_cost("AttachUserPolicy")


def test_fixture_pathfinding():
    nodes, edges, meta = load_graph(FIXTURE)
    graph = AttackGraph(nodes, edges)
    dev = graph.get_node("dev")
    admin = graph.get_node("admin")
    assert dev and admin
    path = graph.find_shortest_path(dev.object_id, admin.object_id)
    assert path is not None
    assert path.length == 3
    kinds = [e.kind for e in path.edges]
    assert kinds[0] == "CanAssume"
    assert "EffectiveAdmin" in kinds


def test_arn_suffix_resolution():
    nodes, edges, _ = load_graph(FIXTURE)
    graph = AttackGraph(nodes, edges)
    # 'dev' should resolve the full user ARN via suffix match.
    node = graph.get_node("dev")
    assert node.object_id.endswith("/dev")


def test_high_value_excludes_synthetic_goal():
    nodes, edges, _ = load_graph(FIXTURE)
    graph = AttackGraph(nodes, edges)
    hvts = graph.find_high_value_targets()
    assert all(not n.properties.get("synthetic_goal") for n in hvts)
    assert any(n.name == "admin-role" for n in hvts)


def test_exploit_runbook_fills_real_arns():
    from awspwn.exploit import candidate_paths, render_runbook

    nodes, edges, meta = load_graph(FIXTURE)
    graph = AttackGraph(nodes, edges)
    dev = graph.get_node("dev")
    paths = candidate_paths(graph, dev.object_id, max_depth=12)
    assert paths, "no candidate paths"
    runbook = render_runbook(paths[0], meta["account"], "us-east-1")
    # Identity hop rendered as an assume-role + export block.
    assert "aws sts assume-role" in runbook
    assert "export AWS_ACCESS_KEY_ID" in runbook
    # Placeholders resolved to concrete values, none left dangling.
    assert "{TARGET_ARN}" not in runbook
    assert "{ROLE_ARN}" not in runbook


def test_exploit_is_runnable_guard():
    from awspwn.exploit import _is_runnable

    assert _is_runnable("aws sts get-caller-identity")
    assert not _is_runnable("aws lambda create-function --zip-file fileb://x.zip")
    assert not _is_runnable("import os\ndef handler(e,c): ...")


def test_nodekind_from_arn():
    assert NodeKind.from_arn("arn:aws:iam::111:role/foo") == NodeKind.IAM_ROLE
    assert NodeKind.from_arn("arn:aws:iam::111:user/bar") == NodeKind.IAM_USER
    assert NodeKind.from_arn("arn:aws:s3:::my-bucket") == NodeKind.S3_BUCKET
    assert NodeKind.from_arn("arn:aws:secretsmanager:us-east-1:111:secret:x") == NodeKind.SECRET


def test_loot_files_are_owner_only(tmp_path):
    import os
    import stat as statmod

    from awspwn.state import State, save_graph, save_state

    loot = tmp_path / "loot"
    st = State(origin_account="111111111111", caller_arn="arn:aws:iam::111111111111:user/dev")
    p = save_state(st, str(loot))
    g = save_graph(st, str(loot))
    assert statmod.S_IMODE(os.stat(loot).st_mode) == 0o700, "loot dir not 0700"
    assert statmod.S_IMODE(p.stat().st_mode) == 0o600, "state.json not 0600"
    assert statmod.S_IMODE(g.stat().st_mode) == 0o600, "graph.json not 0600"
    assert not any(x.endswith(".tmp") for x in os.listdir(loot)), "temp file left behind"


def test_run_never_invokes_a_shell(monkeypatch):
    """A hostile graph.json must not achieve shell injection through _run."""
    from awspwn import exploit

    calls = {}

    class _Proc:
        returncode, stdout, stderr = 0, "", ""

    def _fake_run(args, **kw):
        calls["args"], calls["kw"] = args, kw
        return _Proc()

    monkeypatch.setattr(exploit.subprocess, "run", _fake_run)

    class _Client:
        class identity:
            @staticmethod
            def to_env():
                return {}

    # Shell metacharacters in a substituted value must stay a single literal arg.
    exploit._run("aws iam get-role --role-name 'evil; rm -rf ~'", _Client())
    assert isinstance(calls["args"], list), "command not passed as an argv list"
    assert calls["kw"].get("shell", False) is False, "a shell was used"
    assert calls["args"][0] == "aws"
    assert "evil; rm -rf ~" in calls["args"], "metacharacters were not kept literal"

    # A leading VAR=VALUE prefix is folded into the env, not exec'd as a program.
    calls.clear()
    exploit._run("AWS_REGION=eu-west-1 aws sts get-caller-identity", _Client())
    assert calls["args"] == ["aws", "sts", "get-caller-identity"]
    assert calls["kw"]["env"].get("AWS_REGION") == "eu-west-1"


def test_loot_export_emits_eval_lines(tmp_path, capsys):
    import argparse

    from awspwn import cli
    from awspwn.state import save_captured_cred

    save_captured_cred({"kind": "role-creds", "account": "111", "target_arn": "arn:aws:iam::111:role/admin",
                        "target_name": "admin-role", "access_key": "ASIAX", "secret_key": "sek", "session_token": "tok"}, str(tmp_path))
    save_captured_cred({"kind": "access_key", "account": "111", "target_arn": "arn:aws:iam::111:user/ops",
                        "target_name": "ops", "access_key": "AKIAY", "secret_key": "sec", "session_token": ""}, str(tmp_path))

    def ns(export):
        return argparse.Namespace(loot_dir=str(tmp_path), export=export, show_secrets=False)

    # Session creds -> exports the token.
    assert cli.cmd_loot(ns("admin")) == 0
    cap = capsys.readouterr()
    assert "export AWS_ACCESS_KEY_ID=ASIAX" in cap.out
    assert "export AWS_SESSION_TOKEN=tok" in cap.out
    assert "ephemeral" in cap.err  # info goes to stderr, not stdout

    # Long-term key -> unsets a possibly-stale session token.
    assert cli.cmd_loot(ns("ops")) == 0
    cap = capsys.readouterr()
    assert "export AWS_ACCESS_KEY_ID=AKIAY" in cap.out
    assert "unset AWS_SESSION_TOKEN" in cap.out

    # Ambiguous selection -> nothing eval-able on stdout, non-zero exit.
    assert cli.cmd_loot(ns("")) == 1
    cap = capsys.readouterr()
    assert cap.out.strip() == ""
    assert "multiple" in cap.err


def test_no_cache_bypasses_saved_graph(tmp_path, monkeypatch):
    import argparse
    import shutil

    import pytest

    from awspwn import cli

    loot = tmp_path / "loot"
    loot.mkdir()
    shutil.copy(FIXTURE, loot / "graph.json")  # seed the loot-dir cache
    for k in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(k, raising=False)
    base = dict(data=None, loot_dir=str(loot), profile="", access_key="", secret_key="")

    # Default: the saved graph.json is used.
    graph, _ = cli._graph_or_enum(argparse.Namespace(no_cache=False, **base))
    assert graph.get_node("dev") is not None

    # --no-cache refuses to fall back to the cache when it cannot re-enumerate.
    with pytest.raises(RuntimeError, match="no-cache"):
        cli._graph_or_enum(argparse.Namespace(no_cache=True, **base))
