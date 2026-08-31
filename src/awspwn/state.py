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

from .models import Edge, Finding, Mutation, Node


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
    account: str = ""
    caller_arn: str = ""
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    mutations: list[Mutation] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)

    # ─── mutators ─────────────────────────────────────────────────────────

    def add_node(self, node: Node) -> None:
        for existing in self.nodes:
            if existing.object_id == node.object_id:
                # Merge properties; newest non-empty wins for scalars.
                existing.properties.update(node.properties)
                if node.name and not existing.name:
                    existing.name = node.name
                if node.account and not existing.account:
                    existing.account = node.account
                return
        self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        key = (edge.source_id, edge.target_id, edge.kind)
        for existing in self.edges:
            if (existing.source_id, existing.target_id, existing.kind) == key:
                return
        self.edges.append(edge)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def record_mutation(self, mutation: Mutation) -> None:
        self.mutations.append(mutation)

    def node_map(self) -> dict[str, Node]:
        return {n.object_id: n for n in self.nodes}

    # ─── serialization ────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "account": self.account,
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
            account=d.get("account", ""),
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
        "account": state.account,
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
