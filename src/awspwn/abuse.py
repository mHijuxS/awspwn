"""Abuse database aggregator - merges every edge module into a single lookup.

Mirrors ADPwn's abuse.py: import each ABUSE_DB, merge into MASTER_ABUSE_DB,
synthesize non-abusable structural edges from a name list, and expose the same
helper surface (get_abuse_info / get_steps_for_platform / list_* /
format_command / find_empty_placeholders).
"""

from __future__ import annotations

import re
from typing import Optional

from .models import AbuseInfo, AbuseStep, Platform
from .edges.iam import ABUSE_DB as IAM_DB
from .edges.compute import ABUSE_DB as COMPUTE_DB
from .edges.data import ABUSE_DB as DATA_DB
from .edges.persist import ABUSE_DB as PERSIST_DB
from .edges.org import ABUSE_DB as ORG_DB


# Category -> its edge DB. Drives `awspwn edges` grouping and the merge below.
EDGE_CATEGORIES: dict[str, dict[str, AbuseInfo]] = {
    "iam": IAM_DB,
    "compute": COMPUTE_DB,
    "data": DATA_DB,
    "persist": PERSIST_DB,
    "org": ORG_DB,
}

MASTER_ABUSE_DB: dict[str, AbuseInfo] = {}
for _db in EDGE_CATEGORIES.values():
    MASTER_ABUSE_DB.update(_db)

# Reverse index: edge kind -> category name (for reporting).
EDGE_CATEGORY_OF: dict[str, str] = {}
for _cat, _db in EDGE_CATEGORIES.items():
    for _kind in _db:
        EDGE_CATEGORY_OF[_kind] = _cat


# ─── Non-abusable structural edges ──────────────────────────────────────────
# Traversed by pathfinding but not independently exploitable.
_STRUCTURAL = [
    "AttachedTo",       # policy -> principal attachment
    "ContainedIn",      # resource -> account
    "InstanceProfileFor",  # instance profile -> role
    "TrustedBy",        # role trust relationship (informational direction)
]

for _name in _STRUCTURAL:
    if _name not in MASTER_ABUSE_DB:
        MASTER_ABUSE_DB[_name] = AbuseInfo(
            edge_kind=_name,
            description=(
                f"Structural edge: {_name}. Part of the graph topology but not "
                "independently abusable."
            ),
            is_abusable=False,
        )


def get_abuse_info(edge_kind: str) -> Optional[AbuseInfo]:
    """Look up abuse information for an edge kind."""
    return MASTER_ABUSE_DB.get(edge_kind)


def get_steps_for_platform(abuse_info: AbuseInfo, platform: Platform) -> list[AbuseStep]:
    """Steps for a platform, defaulting to Linux (the operator platform here)."""
    if platform == Platform.WINDOWS and abuse_info.windows_steps:
        return abuse_info.windows_steps
    return abuse_info.linux_steps


def list_abusable_edges() -> list[str]:
    return sorted(k for k, v in MASTER_ABUSE_DB.items() if v.is_abusable)


def list_all_edges() -> list[str]:
    return sorted(MASTER_ABUSE_DB.keys())


def edges_by_category() -> dict[str, list[str]]:
    """Abusable edges grouped by category, for `awspwn edges`."""
    out: dict[str, list[str]] = {cat: [] for cat in EDGE_CATEGORIES}
    for kind, info in MASTER_ABUSE_DB.items():
        if not info.is_abusable:
            continue
        cat = EDGE_CATEGORY_OF.get(kind, "other")
        out.setdefault(cat, []).append(kind)
    return {cat: sorted(kinds) for cat, kinds in out.items() if kinds}


def format_command(command: str, context: dict) -> str:
    """Replace {PLACEHOLDER} tokens with context values.

    Deliberately a str.replace loop, NOT str.format - AWS CLI commands are full
    of literal JSON braces ('--policy-document {...}') that str.format would
    choke on. Unfilled placeholders survive verbatim so the operator can see
    what still needs a value. Copied from ADPwn's abuse.py by design.
    """
    result = command
    for key, value in context.items():
        result = result.replace("{" + key + "}", str(value))
    return result


def find_empty_placeholders(command: str, context: dict) -> list[str]:
    """Placeholder keys present in the command but empty/missing in context."""
    empty: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"\{([A-Z][A-Z0-9_]*)\}", command):
        key = m.group(1)
        if key in seen:
            continue
        seen.add(key)
        if not context.get(key):
            empty.append(key)
    return empty
