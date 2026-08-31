"""Persistent engagement state - the graph, findings, and mutation ledger,
written to <loot_dir>/state.json.

Subcommands compose across invocations (`enum` writes the graph;
`path`/`analyze`/`report` read it back). Adds the mutation ledger that
`awspwn rollback` (phase 3) replays. Captured credential material is never
written here - it is surfaced in the run summary only; state.json holds the
graph, findings, and the API calls + undo params of the mutation ledger.

Engagement data (account IDs, IAM topology, policies, findings, resource names)
is sensitive, so the loot directory is created 0700 and every file written 0600
- owner-only - regardless of the process umask.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from .models import (
    GRANT_PROPERTY_KEYS,
    Edge,
    Finding,
    Mutation,
    Node,
    NodeKind,
    merge_grant_properties,
)


DEFAULT_LOOT_DIR = "./awspwn-loot"
STATE_FILENAME = "state.json"
GRAPH_FILENAME = "graph.json"
# Raw captured/created credential material (access keys, role session creds,
# secrets that held keys). Owner-only (0600). Kept OUT of state.json, which stays
# redacted and shareable. `pwn` reuses these across runs so a mid-run failure
# does not orphan a created key or re-mint a duplicate on the next run.
CAPTURED_FILENAME = "captured-creds.jsonl"


@dataclass
class State:
    # The engagement's STARTING account. Nodes carry their own `account`, so a
    # cross-account pivot during `roam` grows one graph spanning several accounts
    # without ever resetting - only the top-level `enum` entry treats a genuinely
    # different starting account as a fresh engagement. Serialized as "account"
    # for back-compat with existing state.json / graph.json.
    origin_account: str = ""
    caller_arn: str = ""
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    mutations: list[Mutation] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)

    # ─── mutators ─────────────────────────────────────────────────────────

    def add_node(self, node: Node) -> None:
        # Must mirror AttackGraph.add_node exactly, or the live graph enriches a
        # node (region, concrete kind) while the persisted state reloads the
        # poorer copy after save/load.
        for existing in self.nodes:
            if existing.object_id == node.object_id:
                # Grant/permission keys merge by snapshot authority (below);
                # everything else is last-writer-wins.
                for k, v in node.properties.items():
                    if k not in GRANT_PROPERTY_KEYS:
                        existing.properties[k] = v
                merge_grant_properties(existing.properties, node.properties)
                if node.name and not existing.name:
                    existing.name = node.name
                if node.account and not existing.account:
                    existing.account = node.account
                if node.region and not existing.region:
                    existing.region = node.region
                if existing.kind == NodeKind.UNKNOWN and node.kind != NodeKind.UNKNOWN:
                    existing.kind = node.kind
                return
        self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        """Insert `edge`, or ENRICH the existing one on an (src,tgt,kind) match.

        A later vantage can only add confidence, never remove it: properties are
        merged, and `conditional` may go True->False (a fresh vantage confirmed
        the edge) but never False->True. This is what lets simulate refinement
        and repeated `collect_from` passes upgrade an edge in place instead of
        silently dropping the improved copy."""
        key = (edge.source_id, edge.target_id, edge.kind)
        for existing in self.edges:
            if (existing.source_id, existing.target_id, existing.kind) == key:
                existing.properties.update(edge.properties)
                if existing.conditional and not edge.conditional:
                    existing.conditional = False
                return
        self.edges.append(edge)

    def remove_edge(self, source_id: str, target_id: str, kind: str) -> bool:
        """Drop an edge (e.g. simulate returned an explicit deny). Returns True
        if one was removed. The AttackGraph keeps its own adjacency indexes, so
        callers that hold a live graph must remove it there too."""
        before = len(self.edges)
        self.edges = [
            e for e in self.edges
            if (e.source_id, e.target_id, e.kind) != (source_id, target_id, kind)
        ]
        return len(self.edges) != before

    def add_finding(self, finding: Finding) -> None:
        """Append, deduplicating on (severity, category, title, arn) so repeated
        collections from the same vantage do not pile up identical findings.
        The arn distinguishes the same denial seen from two different vantages -
        per-principal denial is per-principal intel, kept distinct on purpose."""
        key = (finding.severity, finding.category, finding.title, finding.arn)
        for existing in self.findings:
            if (existing.severity, existing.category, existing.title, existing.arn) == key:
                return
        self.findings.append(finding)

    def record_mutation(self, mutation: Mutation) -> None:
        self.mutations.append(mutation)

    def node_map(self) -> dict[str, Node]:
        return {n.object_id: n for n in self.nodes}

    # ─── serialization ────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "account": self.origin_account,
            "caller_arn": self.caller_arn,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "findings": [f.to_dict() for f in self.findings],
            "mutations": [m.to_dict() for m in self.mutations],
            "denied": sorted(set(self.denied)),
            "artifacts": self.artifacts,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "State":
        state = cls(
            origin_account=d.get("account", ""),
            caller_arn=d.get("caller_arn", ""),
            denied=list(d.get("denied", [])),
            artifacts=dict(d.get("artifacts", {})),
        )
        for n in d.get("nodes", []):
            state.nodes.append(Node.from_dict(n))
        for e in d.get("edges", []):
            state.edges.append(Edge.from_dict(e))
        for f in d.get("findings", []):
            state.findings.append(Finding.from_dict(f))
        for m in d.get("mutations", []):
            state.mutations.append(Mutation.from_dict(m))
        return state


# ─── Path helpers ───────────────────────────────────────────────────────────


def loot_dir_path(loot_dir: Optional[str] = None) -> Path:
    return Path(loot_dir or DEFAULT_LOOT_DIR).expanduser().resolve()


def secure_mkdir(d: Path) -> Path:
    """Create `d` (and parents) and restrict it to the owner (0700)."""
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass  # best-effort: non-POSIX filesystems may not support chmod
    return d


def write_private_file(path: Union[str, Path], text: str) -> Path:
    """Atomically write `text` to `path` with owner-only (0600) permissions.

    Uses os.open with an explicit mode so the file is 0600 from creation - never
    briefly world-readable under a 022 umask - and writes via a temp file +
    os.replace so a reader never sees a half-written document.
    """
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)  # enforce even if a stale tmp pre-existed
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def append_private_file(path: Union[str, Path], text: str) -> Path:
    """Append `text` to `path`, creating it 0600 if new and enforcing 0600."""
    path = Path(path)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


# ─── Captured-credential store (owner-only loot) ────────────────────────────


def captured_creds_path(loot_dir: Optional[str] = None) -> Path:
    return loot_dir_path(loot_dir) / CAPTURED_FILENAME


def save_captured_cred(entry: dict, loot_dir: Optional[str] = None) -> Path:
    """Append one captured/created credential to the 0600 loot store."""
    secure_mkdir(loot_dir_path(loot_dir))
    p = captured_creds_path(loot_dir)
    return append_private_file(p, json.dumps(entry, sort_keys=False) + "\n")


def load_captured_creds(loot_dir: Optional[str] = None) -> list[dict]:
    p = captured_creds_path(loot_dir)
    out: list[dict] = []
    if not p.exists():
        return out
    try:
        with p.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def find_captured_cred(loot_dir: Optional[str], kind: str, target_arn: str) -> Optional[dict]:
    """The most recently stored credential of `kind` for `target_arn`, or None."""
    match = None
    for entry in load_captured_creds(loot_dir):
        if entry.get("kind") == kind and entry.get("target_arn") == target_arn:
            match = entry
    return match


def state_path(loot_dir: Optional[str] = None) -> Path:
    return loot_dir_path(loot_dir) / STATE_FILENAME


def load_state(loot_dir: Optional[str] = None) -> State:
    p = state_path(loot_dir)
    if p.exists():
        try:
            with p.open("r") as f:
                return State.from_dict(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass
    return State()


def save_state(state: State, loot_dir: Optional[str] = None) -> Path:
    d = secure_mkdir(loot_dir_path(loot_dir))
    return write_private_file(d / STATE_FILENAME,
                              json.dumps(state.to_dict(), indent=2, sort_keys=False))


def save_graph(state: State, loot_dir: Optional[str] = None) -> Path:
    """Write a standalone graph.json (nodes+edges only) for `awspwn load`."""
    d = secure_mkdir(loot_dir_path(loot_dir))
    doc = {
        "account": state.origin_account,
        "caller_arn": state.caller_arn,
        "nodes": [n.to_dict() for n in state.nodes],
        "edges": [e.to_dict() for e in state.edges],
    }
    return write_private_file(d / GRAPH_FILENAME,
                              json.dumps(doc, indent=2, sort_keys=False))


def load_graph(path: str) -> tuple[dict[str, Node], list[Edge], dict]:
    """Load a graph.json (or a full state.json) into (nodes, edges, meta)."""
    with open(path, "r") as f:
        doc = json.load(f)
    nodes = {n["object_id"]: Node.from_dict(n) for n in doc.get("nodes", [])}
    edges = [Edge.from_dict(e) for e in doc.get("edges", [])]
    meta = {"account": doc.get("account", ""), "caller_arn": doc.get("caller_arn", "")}
    return nodes, edges, meta
