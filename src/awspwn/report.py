"""Reporting - terminal (severity-grouped), JSON, and loot renderers.

Mirrors ADScout's report.py: a single Severity model, CRITICAL→INFO grouping,
INFO hidden unless verbose, evidence truncated. Adds graph-shaped renderers
(stats, high-value targets, attack paths) since AWSPwn's product is a graph, not
a flat finding list.
"""

from __future__ import annotations

import json
from collections import defaultdict

from .abuse import EDGE_CATEGORY_OF, get_abuse_info
from .colors import C, _bold, _color, _dim
from .graph import AttackGraph
from .models import AttackPath, BlastRadius, Finding, SEV_LABELS, Severity
from .state import CAPTURED_FILENAME, State


_SEV_COLOR = {
    Severity.CRITICAL: C.RED,
    Severity.HIGH: C.RED,
    Severity.MEDIUM: C.YELLOW,
    Severity.LOW: C.BLUE,
    Severity.INFO: C.DIM,
}

_BLAST_COLOR = {
    BlastRadius.READ: C.GREEN,
    BlastRadius.MUTATE: C.YELLOW,
    BlastRadius.DESTRUCTIVE: C.RED,
    BlastRadius.EXTERNAL_EXPOSURE: C.MAGENTA,
}


# ─── Findings ───────────────────────────────────────────────────────────────


def render_findings(findings: list[Finding], *, verbose: bool = False) -> str:
    by_sev: dict[Severity, list[Finding]] = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)

    lines: list[str] = []
    for sev in Severity:
        bucket = by_sev.get(sev, [])
        if not bucket:
            continue
        if sev == Severity.INFO and not verbose:
            lines.append(_dim(f"  [{SEV_LABELS[sev]}] {len(bucket)} info finding(s) - use -v to show"))
            continue
        label = _color(f"── {sev.name} ({len(bucket)}) ", _SEV_COLOR[sev])
        lines.append(label + _dim("─" * max(0, 60 - len(sev.name))))
        for f in bucket:
            tag = _color(SEV_LABELS[sev], _SEV_COLOR[sev])
            lines.append(f"  [{tag}] {_bold(f.title)}")
            if f.detail:
                lines.append(f"        {f.detail}")
            if f.arn:
                lines.append(_dim(f"        {f.arn}"))
            if f.evidence:
                ev_lines = f.evidence.splitlines()
                shown = ev_lines[:8]
                for ev in shown:
                    lines.append(_dim(f"        │ {ev}"))
                if len(ev_lines) > 8:
                    lines.append(_dim(f"        │ … {len(ev_lines) - 8} more line(s)"))
        lines.append("")
    if not lines:
        return _dim("  (no findings)")
    return "\n".join(lines)


# ─── Graph stats ────────────────────────────────────────────────────────────


def render_stats(graph: AttackGraph) -> str:
    s = graph.stats
    lines = [_bold(f"  Graph: {s['total_nodes']} nodes, {s['total_edges']} edges")]
    lines.append(_dim("  Node kinds:"))
    for kind, count in list(s["node_kinds"].items())[:20]:
        bar = "█" * min(count, 40)
        lines.append(f"    {kind:24} {count:4}  {_color(bar, C.CYAN)}")
    lines.append(_dim("  Edge kinds:"))
    for kind, count in list(s["edge_kinds"].items())[:20]:
        bar = "█" * min(count, 40)
        lines.append(f"    {kind:24} {count:4}  {_color(bar, C.BLUE)}")
    return "\n".join(lines)


def render_high_value(graph: AttackGraph) -> str:
    hvts = graph.find_high_value_targets()
    if not hvts:
        return _dim("  (no high-value targets identified)")
    lines = [_bold(f"  High-value targets ({len(hvts)}):")]
    for n in sorted(hvts, key=lambda x: x.label):
        why = []
        if n.properties.get("synthetic_goal"):
            continue  # the admin goal node isn't itself a "target"
        if n.properties.get("is_admin"):
            why.append("effective-admin")
        if n.properties.get("is_org_management"):
            why.append("org-management")
        if n.properties.get("trusts_external"):
            why.append("trusts-external")
        if n.properties.get("trusts_wildcard"):
            why.append("trusts-*")
        tag = _color(n.kind.value, C.MAGENTA)
        reason = _dim(" [" + ",".join(why) + "]") if why else ""
        lines.append(f"    {_color('★', C.YELLOW)} {n.label}  {tag}{reason}")
    return "\n".join(lines)


# ─── Attack paths ───────────────────────────────────────────────────────────


def render_path(path: AttackPath, *, index: int = 0) -> str:
    header = _bold(f"  Path #{index + 1}  (cost {path.cost}, {path.length} hop(s))")
    lines = [header]
    for i, edge in enumerate(path.edges):
        src = path.nodes[i]
        dst = path.nodes[i + 1]
        info = get_abuse_info(edge.kind)
        blast = info.blast_radius if info else BlastRadius.READ
        blast_tag = _color(blast.value, _BLAST_COLOR.get(blast, C.WHITE))
        arrow = _color("──▶", C.DIM)
        kind = _color(edge.kind, C.CYAN)
        cond = _color(" (conditional)", C.YELLOW) if edge.conditional else ""
        lines.append(f"    {src.label}")
        lines.append(f"      {arrow} [{kind}] {_dim('→')} {dst.label}  {blast_tag}{cond}")
    return "\n".join(lines)


def render_paths(paths: list[AttackPath]) -> str:
    if not paths:
        return _color("  No attack path found.", C.YELLOW)
    return "\n\n".join(render_path(p, index=i) for i, p in enumerate(paths))


# ─── Edge catalogue (`awspwn edges`) ────────────────────────────────────────


def render_edge_catalogue(by_category: dict[str, list[str]]) -> str:
    cat_titles = {
        "iam": "IAM privilege escalation",
        "compute": "Compute lateral movement",
        "data": "Data & secrets",
        "persist": "Persistence & backdoors",
        "org": "Organization & cross-account",
    }
    lines = []
    total = sum(len(v) for v in by_category.values())
    lines.append(_bold(f"  {total} abusable edge types\n"))
    for cat, kinds in by_category.items():
        title = cat_titles.get(cat, cat)
        lines.append(_color(f"  {title} ({len(kinds)})", C.CYAN))
        for kind in kinds:
            info = get_abuse_info(kind)
            blast = info.blast_radius if info else BlastRadius.READ
            blast_tag = _color(blast.value, _BLAST_COLOR.get(blast, C.WHITE))
            lines.append(f"    {kind:34} {blast_tag}")
        lines.append("")
    return "\n".join(lines)


def render_edge_info(kind: str) -> str:
    info = get_abuse_info(kind)
    if info is None:
        return _color(f"  Unknown edge type: {kind}", C.RED)
    lines = [_bold(f"  {kind}")]
    cat = EDGE_CATEGORY_OF.get(kind, "")
    if cat:
        lines.append(_dim(f"  category: {cat}"))
    blast_tag = _color(info.blast_radius.value, _BLAST_COLOR.get(info.blast_radius, C.WHITE))
    lines.append(f"  blast radius: {blast_tag}")
    lines.append("")
    lines.append(f"  {info.description}")
    if info.required_permissions:
        lines.append("")
        lines.append(_dim("  required permissions:"))
        for p in info.required_permissions:
            lines.append(f"    - {p}")
    if info.linux_steps:
        lines.append("")
        lines.append(_color("  Steps:", C.CYAN))
        for i, step in enumerate(info.linux_steps, 1):
            marker = _dim("(cleanup)") if step.is_cleanup else ""
            step_blast = _color(step.blast_radius.value, _BLAST_COLOR.get(step.blast_radius, C.WHITE))
            lines.append(f"    {i}. {_bold(step.description)} {marker} [{step_blast}]")
            for cmd_line in step.command.splitlines():
                lines.append(_color(f"       {cmd_line}", C.GREEN))
            if step.opsec_note:
                lines.append(_dim(f"       opsec: {step.opsec_note}"))
    if info.opsec_considerations:
        lines.append("")
        lines.append(_color("  OPSEC:", C.YELLOW))
        for ln in _wrap(info.opsec_considerations, 72):
            lines.append(f"    {ln}")
    if info.references:
        lines.append("")
        lines.append(_dim("  references:"))
        for r in info.references:
            lines.append(_dim(f"    {r}"))
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


# ─── JSON / loot ────────────────────────────────────────────────────────────


def render_json(state: State) -> str:
    return json.dumps(state.to_dict(), indent=2, sort_keys=False)


def cred_account(c: dict) -> str:
    """Account a captured credential belongs to (explicit field, else from ARN)."""
    acct = c.get("account", "")
    if acct:
        return acct
    arn = c.get("target_arn", "") or c.get("arn", "")
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def render_captured(creds: list[dict], *, show_secrets: bool = False, current_account: str = "") -> str:
    """Inventory of the captured-credential loot store. Session/ephemeral creds
    and creds from a different account than the current graph are flagged so a
    stale entry from a previous lab is obvious. Secret keys / session tokens are
    shown only with show_secrets (they live 0600 in the store file)."""
    if not creds:
        return _dim("  (no captured credentials)")
    lines = [_bold(f"  Captured credentials ({len(creds)}):")]
    stale = False
    for c in creds:
        target = c.get("target_name") or c.get("target_arn") or "?"
        akid = c.get("access_key", "")
        acct = cred_account(c)
        tags = []
        if c.get("session_token"):
            tags.append(_color("session/ephemeral", C.YELLOW))
        if current_account and acct and acct != current_account:
            tags.append(_color(f"account {acct} (graph is {current_account})", C.RED))
            stale = True
        elif acct:
            tags.append(_dim(acct))
        if c.get("expiration"):
            tags.append(_dim("exp " + c["expiration"]))
        tail = ("  " + "  ".join(tags)) if tags else ""
        lines.append(f"    {_color('★', C.YELLOW)} {c.get('kind', '?'):14} {target:32} "
                     f"{_color(akid, C.CYAN)}{tail}")
        if show_secrets:
            sk, tok = c.get("secret_key", ""), c.get("session_token", "")
            export = f"export AWS_ACCESS_KEY_ID={akid} AWS_SECRET_ACCESS_KEY={sk}"
            if tok:
                export += f" AWS_SESSION_TOKEN={tok}"
            lines.append(_color(f"        {export}", C.GREEN))
    if stale:
        lines.append(_color("    ! some creds are from a different account than the current graph - "
                            "likely a previous lab; they will not authenticate.", C.RED))
    if not show_secrets:
        lines.append(_dim(f"    secrets are in {CAPTURED_FILENAME} (0600) - pass --show-secrets to print them"))
    return "\n".join(lines)


def render_loot(state: State) -> str:
    lines = [_bold("  Loot summary")]
    lines.append(f"    account:  {state.account}")
    lines.append(f"    caller:   {state.caller_arn}")
    lines.append(f"    nodes:    {len(state.nodes)}")
    lines.append(f"    edges:    {len(state.edges)}")
    lines.append(f"    findings: {len(state.findings)}")
    lines.append(f"    denied:   {len(set(state.denied))} action(s)")
    lines.append(f"    mutations:{len(state.mutations)}")
    if state.mutations:
        lines.append("")
        lines.append(_color("  Mutation ledger (rollback with `awspwn rollback`):", C.YELLOW))
        for m in state.mutations:
            status = _color("reverted", C.GREEN) if m.reverted else _color("LIVE", C.RED)
            lines.append(f"    [{status}] {m.api}  ({m.blast_radius})")
    return "\n".join(lines)
