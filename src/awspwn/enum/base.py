"""Enumeration base - the ServiceEnumerator contract and the ThreadPoolExecutor
fan-out that runs every enumerator across every relevant region.

Each enumerator is isolated in try/except so one denied service (the norm on a
scoped engagement) never aborts the sweep. AccessDenied is recorded as an INFO
finding, not an error - knowing what you CANNOT see is itself intel.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from ..aws_client import AwsClient, classify, ErrorClass
from ..colors import C, _color
from ..models import Edge, Finding, Node, NodeKind, Severity


def minimal_role_node(role_arn: str, region: str = "") -> Node:
    """A bare IAM_ROLE node for a role referenced by a resource (a Lambda's
    execution role, an ECS task role, an EC2 instance-profile role). Carries no
    policy/grant properties - it exists so the role is a real graph node even with
    no IAM read, and merges with a richer node if IAM enumeration also sees it."""
    acct = role_arn.split(":")[4] if role_arn.count(":") >= 4 else ""
    return Node(object_id=role_arn, name=role_arn.rsplit("/", 1)[-1],
                kind=NodeKind.IAM_ROLE, account=acct, region=region)


@dataclass
class EnumResult:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Services/actions that came back AccessDenied - the reachability boundary.
    denied: list[str] = field(default_factory=list)

    def extend(self, other: "EnumResult") -> None:
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)
        self.findings.extend(other.findings)
        self.denied.extend(other.denied)


class ServiceEnumerator:
    """Base class for a per-service enumerator.

    Subclasses set `name` and `service` and implement `enumerate`. `is_global`
    is derived from the service so the runner knows whether to fan out per
    region or call once.
    """

    name: str = "base"
    service: str = ""
    is_global: bool = False

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        raise NotImplementedError

    # ─── Helpers shared by all enumerators ─────────────────────────────────

    def _denied(self, action: str, region: str = "") -> Finding:
        where = f" ({region})" if region else ""
        return Finding(
            severity=Severity.INFO,
            category="enum",
            title=f"AccessDenied: {action}{where}",
            detail="Current identity cannot perform this action; results may be incomplete.",
        )

    def _handle(self, exc: Exception, action: str, region: str, result: EnumResult) -> bool:
        """Record a boto exception on `result`. Returns True if it was benign
        (denied/not-found - keep going), False if it should bubble up."""
        cls = classify(exc)
        if cls in (ErrorClass.ACCESS_DENIED, ErrorClass.NOT_FOUND):
            result.denied.append(action)
            if cls == ErrorClass.ACCESS_DENIED:
                result.findings.append(self._denied(action, region))
            return True
        if cls in (ErrorClass.REGION,):
            return True  # region not enabled / no endpoint - skip quietly
        return False


def run_all(
    client: AwsClient,
    enumerators: list[ServiceEnumerator],
    regions: Optional[list[str]] = None,
    max_workers: int = 12,
    verbose: bool = False,
) -> EnumResult:
    """Fan out enumerators across regions and merge their results.

    Global-service enumerators run once; regional ones run per region. The
    standard repo pattern: ThreadPoolExecutor over I/O-bound work.
    """
    regions = regions or ["us-east-1"]
    combined = EnumResult()

    # Build the task list: (enumerator, region).
    tasks: list[tuple[ServiceEnumerator, str]] = []
    for enum in enumerators:
        if enum.is_global:
            tasks.append((enum, "us-east-1"))
        else:
            for region in regions:
                tasks.append((enum, region))

    def _run(enum: ServiceEnumerator, region: str) -> EnumResult:
        try:
            return enum.enumerate(client, region)
        except Exception as exc:  # noqa: BLE001 - one enumerator must not kill the sweep
            res = EnumResult()
            res.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="enum",
                    title=f"Enumerator {enum.name} failed in {region}",
                    detail=str(exc),
                )
            )
            return res

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run, enum, region): (enum, region) for enum, region in tasks}
        for fut in as_completed(futures):
            enum, region = futures[fut]
            res = fut.result()
            combined.extend(res)
            if verbose:
                tag = _color(f"[{enum.name}/{region}]", C.DIM)
                print(
                    f"  {tag} nodes:{len(res.nodes)} edges:{len(res.edges)} "
                    f"findings:{len(res.findings)} denied:{len(res.denied)}"
                )

    return combined
