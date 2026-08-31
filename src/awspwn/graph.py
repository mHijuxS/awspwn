"""Graph operations - pathfinding, traversal, and analysis over the AWS graph.

Ported from ADPwn's graph.py. The algorithms are identical (Dijkstra / DFS /
BFS); what changes is the edge taxonomy and one AWS-specific addition: a
blast-radius surcharge in `_edge_cost`, so pathfinding prefers the quietest
route to admin rather than merely the shortest one.
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from typing import Optional

from .models import AttackPath, BLAST_SURCHARGE, Edge, Node, NodeKind

# Purely structural - carries no exploitation value, skipped in reachability.
LAYOUT_EDGES = {
    "AttachedTo",
    "ContainedIn",
    "InstanceProfileFor",
    "TrustedBy",
}

# Membership: traversable, because AddUserToGroup chains through it.
MEMBERSHIP_EDGES = {"MemberOf"}

STRUCTURAL_EDGES = LAYOUT_EDGES | MEMBERSHIP_EDGES

# Direct, high-impact identity gains.
HIGH_VALUE_EDGES = {
    "CanAssume",
    "AssumeRoleCrossAccount",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "UpdateAssumeRolePolicy",
    "GetSecretValue",
    "ReadSSMParameter",
    "RunInstanceWithRole",
    "CreateLambdaWithRole",
    "UpdateLambdaCode",
    "SSMSendCommand",
    "IMDSCredentialTheft",
    "RoleTrustBackdoor",
    "OrgManagementAccountAccess",
    "IdentityCenterAssign",
}

# Names that mean "this principal effectively owns the account".
_ADMIN_ROLE_NAMES = {
    "organizationaccountaccessrole",
    "awscontroltowerexecution",
    "administrator",
    "administratoraccess",
    "admin",
}

_ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}


def _blast_surcharge(kind: str) -> int:
    """Extra cost for noisy/dangerous edges. Looked up lazily so graph.py stays
    importable without pulling in every edge module."""
    from .abuse import get_abuse_info  # local import avoids a hard import cycle

    info = get_abuse_info(kind)
    if info is None:
        return 0
    return BLAST_SURCHARGE.get(info.blast_radius, 0)


def _edge_cost(kind: str) -> int:
    if kind in HIGH_VALUE_EDGES:
        base = 1
    elif kind in MEMBERSHIP_EDGES:
        base = 3
    elif kind in LAYOUT_EDGES:
        base = 5
    else:
        base = 2
    return base + _blast_surcharge(kind)


class AttackGraph:
    """Graph structure optimized for AWS attack-path discovery."""

    def __init__(self, nodes: dict[str, Node], edges: list[Edge]):
        self.nodes = nodes
        self.edges = edges
        self._adjacency: dict[str, list[Edge]] = defaultdict(list)
        self._reverse_adj: dict[str, list[Edge]] = defaultdict(list)
        self._build_adjacency()

    def _build_adjacency(self) -> None:
        for edge in self.edges:
            self._adjacency[edge.source_id].append(edge)
            self._reverse_adj[edge.target_id].append(edge)

    # ─── Lookup ────────────────────────────────────────────────────────────

    def get_node(self, identifier: str) -> Optional[Node]:
        """Lookup by ARN, by name, or by ARN suffix ('dev' -> .../user/dev)."""
        if identifier in self.nodes:
            return self.nodes[identifier]
        id_lower = identifier.lower()
        for node in self.nodes.values():
            if node.name.lower() == id_lower or node.object_id.lower() == id_lower:
                return node
        # ARN suffix match - the common shorthand on an engagement.
        matches = [
            n for n in self.nodes.values() if n.object_id.lower().endswith("/" + id_lower)
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    def search_nodes(
        self, query: str, kind: Optional[NodeKind] = None, limit: int = 20
    ) -> list[Node]:
        q = query.lower()
        results = []
        for node in self.nodes.values():
            if kind and node.kind != kind:
                continue
            if q in node.name.lower() or q in node.object_id.lower():
                results.append(node)
                if len(results) >= limit:
                    break
        return results

    def nodes_of_kind(self, kind: NodeKind) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    # ─── Mutation (live graph updates mid-pwn) ─────────────────────────────

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.object_id, node)

    def add_edge(self, edge: Edge) -> None:
        """Add an edge at runtime - e.g. after AddUserToGroup succeeds."""
        self.edges.append(edge)
        self._adjacency[edge.source_id].append(edge)
        self._reverse_adj[edge.target_id].append(edge)

    def outgoing_edges(self, node_id: str) -> list[Edge]:
        return self._adjacency.get(node_id, [])

    def incoming_edges(self, node_id: str) -> list[Edge]:
        return self._reverse_adj.get(node_id, [])

    # ─── Pathfinding ───────────────────────────────────────────────────────

    def find_shortest_path(
        self, source_id: str, target_id: str, max_depth: int = 15
    ) -> Optional[AttackPath]:
        """Dijkstra - cheapest (shortest × quietest) attack path."""
        if source_id == target_id:
            return None

        dist = {source_id: 0}
        prev: dict[str, tuple[str, Edge]] = {}
        visited: set[str] = set()
        heap = [(0, source_id)]

        while heap:
            cost, current = heapq.heappop(heap)
            if current in visited:
                continue
            visited.add(current)

            if current == target_id:
                break

            if cost > max_depth * 5:
                continue

            for edge in self._adjacency.get(current, []):
                neighbor = edge.target_id
                if neighbor in visited:
                    continue
                new_cost = cost + _edge_cost(edge.kind)
                if neighbor not in dist or new_cost < dist[neighbor]:
                    dist[neighbor] = new_cost
                    prev[neighbor] = (current, edge)
                    heapq.heappush(heap, (new_cost, neighbor))

        if target_id not in prev:
            return None

        path_edges = []
        path_node_ids = [target_id]
        current = target_id
        while current in prev:
            parent, edge = prev[current]
            path_edges.append(edge)
            path_node_ids.append(parent)
            current = parent

        path_edges.reverse()
        path_node_ids.reverse()

        path_nodes = [
            self.nodes.get(nid, Node(object_id=nid, name=nid)) for nid in path_node_ids
        ]

        return AttackPath(
            nodes=path_nodes, edges=path_edges, cost=dist.get(target_id, 0)
        )

    def find_all_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 8,
        max_paths: int = 10,
    ) -> list[AttackPath]:
        """DFS with backtracking - every distinct path, cheapest first."""
        paths: list[AttackPath] = []

        def dfs(current, target, visited, path_nodes, path_edges, depth):
            if len(paths) >= max_paths or depth > max_depth:
                return
            if current == target:
                nodes_list = [
                    self.nodes.get(nid, Node(object_id=nid, name=nid))
                    for nid in path_nodes
                ]
                paths.append(
                    AttackPath(
                        nodes=nodes_list,
                        edges=list(path_edges),
                        cost=sum(_edge_cost(e.kind) for e in path_edges),
                    )
                )
                return

            for edge in self._adjacency.get(current, []):
                neighbor = edge.target_id
                if neighbor not in visited:
                    visited.add(neighbor)
                    path_nodes.append(neighbor)
                    path_edges.append(edge)
                    dfs(neighbor, target, visited, path_nodes, path_edges, depth + 1)
                    path_edges.pop()
                    path_nodes.pop()
                    visited.discard(neighbor)

        dfs(source_id, target_id, {source_id}, [source_id], [], 0)
        paths.sort(key=lambda p: p.cost)
        return paths

    def reachable_from(self, source_id: str, max_depth: int = 6) -> dict[str, AttackPath]:
        """BFS reachability map: node_id -> path that gets you there."""
        reachable: dict[str, AttackPath] = {}
        visited = {source_id}
        start = self.nodes.get(source_id, Node(object_id=source_id, name=source_id))
        queue: list[tuple[str, list[Node], list[Edge]]] = [(source_id, [start], [])]

        while queue:
            current, path_nodes, path_edges = queue.pop(0)
            if len(path_edges) >= max_depth:
                continue

            for edge in self._adjacency.get(current, []):
                neighbor = edge.target_id
                if neighbor in visited or edge.kind in LAYOUT_EDGES:
                    continue

                visited.add(neighbor)
                new_nodes = path_nodes + [
                    self.nodes.get(neighbor, Node(object_id=neighbor, name=neighbor))
                ]
                new_edges = path_edges + [edge]
                reachable[neighbor] = AttackPath(
                    nodes=new_nodes,
                    edges=new_edges,
                    cost=sum(_edge_cost(e.kind) for e in new_edges),
                )
                queue.append((neighbor, new_nodes, new_edges))

        return reachable

    def actionable_edges(self, node_id: str) -> list[tuple[Edge, Node]]:
        """Outgoing edges worth acting on, deduped by (kind, target)."""
        results = []
        seen: set[tuple[str, str]] = set()
        for edge in self._adjacency.get(node_id, []):
            if edge.kind in LAYOUT_EDGES:
                continue
            key = (edge.kind, edge.target_id)
            if key in seen:
                continue
            seen.add(key)
            target = self.nodes.get(edge.target_id)
            if target:
                results.append((edge, target))
        return results

    # ─── High-value target identification ──────────────────────────────────

    def find_high_value_targets(self) -> list[Node]:
        """Principals whose compromise is effectively game over.

        The AWS analogue of ADPwn's Domain Admins / DCs / adminCount check.
        """
        targets = []
        for node in self.nodes.values():
            if self.is_high_value(node):
                targets.append(node)
        return targets

    def is_high_value(self, node: Node) -> bool:
        if node.properties.get("synthetic_goal"):
            return False  # the abstract admin goal is a marker, not a target
        if node.kind == NodeKind.ROOT_USER:
            return True
        if node.kind == NodeKind.ORGANIZATION:
            return True
        if node.properties.get("is_admin"):
            return True
        if node.properties.get("is_org_management"):
            return True
        name_lower = (node.name or "").lower()
        if node.kind == NodeKind.IAM_ROLE and name_lower in _ADMIN_ROLE_NAMES:
            return True
        attached = node.properties.get("attached_policies") or []
        if any(p in _ADMIN_POLICY_ARNS for p in attached):
            return True
        return False

    def find_admin_principals(self) -> list[Node]:
        """Principals with an effective Action:* / Resource:* grant."""
        return [
            n
            for n in self.nodes.values()
            if n.is_principal and n.properties.get("is_admin")
        ]

    def find_externally_trusted_roles(self) -> list[Node]:
        """Roles whose trust policy admits a principal outside this account."""
        return [
            n
            for n in self.nodes.values()
            if n.kind == NodeKind.IAM_ROLE
            and (
                n.properties.get("trusts_external")
                or n.properties.get("trusts_wildcard")
            )
        ]

    def find_public_resources(self) -> list[Node]:
        """Resources whose resource policy or ACL admits Principal:*."""
        return [n for n in self.nodes.values() if n.properties.get("public")]

    # ─── Stats ─────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        node_kinds: dict[str, int] = defaultdict(int)
        edge_kinds: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            node_kinds[node.kind.value] += 1
        for edge in self.edges:
            edge_kinds[edge.kind] += 1
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_kinds": dict(sorted(node_kinds.items(), key=lambda x: -x[1])),
            "edge_kinds": dict(sorted(edge_kinds.items(), key=lambda x: -x[1])),
        }
