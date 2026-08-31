"""Rollback engine - replay the mutation ledger LIFO to undo a `pwn` run.

Every mutating step the exploitation engine runs records a `Mutation` on the
state ledger (state.json) carrying a fully-specified undo: `undo_api`
(e.g. "iam:DetachUserPolicy") plus `undo_params` (the boto3 kwargs for it). This
module walks the ledger newest-first and calls each undo, so changes are reversed
in the opposite order they were made - the AWS analogue of unwinding a
transaction, and the safety net that makes automated exploitation defensible.

Design notes:
  * The undo is data, not code: `undo_api` maps to a boto3 client method via
    botocore's own `xform_name`, so no hand-maintained dispatch table drifts out
    of sync with the edge DB. Overwrite-style edges (UpdateAssumeRolePolicy,
    SetDefaultPolicyVersion, PutUserPolicy) capture the original document at
    execution time and store the *restore* call directly in `undo_params`, so
    rollback is uniform - every mutation is undone by one call.
  * Idempotent: a mutation already marked `reverted` is skipped, and the ledger
    is persisted after each successful undo, so an interrupted rollback resumes
    cleanly.
  * Best-effort: one undo that fails (the resource is already gone, a dependency
    still references it) never aborts the rest - it is reported and the run
    continues. A NoSuchEntity/NotFound is treated as "already undone".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from botocore import xform_name

from .aws_client import AwsClient, ErrorClass, classify
from .colors import C, _color, _dim
from .models import Mutation
from .state import State, save_state

# Reserved keys a strategy may stash in undo_params for rollback's own use,
# stripped before the boto3 call. `_region` pins a regional undo to the region
# the forward call ran in (IAM/STS are global and need none).
_RESERVED_PREFIX = "_"


@dataclass
class RollbackReport:
    reverted: list[Mutation] = field(default_factory=list)
    failed: list[tuple[Mutation, str]] = field(default_factory=list)
    skipped: int = 0

    @property
    def ok(self) -> bool:
        return not self.failed


def _service_and_method(undo_api: str) -> tuple[str, str]:
    """'iam:DetachUserPolicy' -> ('iam', 'detach_user_policy')."""
    if ":" not in undo_api:
        raise ValueError(f"malformed undo_api (no service prefix): {undo_api!r}")
    service, action = undo_api.split(":", 1)
    return service, xform_name(action)


def _role_arn_from(principal_arn: str) -> Optional[str]:
    """The assumable IAM role ARN for a principal, or None if it is a user/root.

    A mutation made as an assumed role records principal_used as an STS
    assumed-role ARN (arn:aws:sts::ACCT:assumed-role/ROLE/session); to undo it
    with the same authority we must re-assume ROLE.
    """
    if ":assumed-role/" in principal_arn:
        parts = principal_arn.split(":")
        account = parts[4] if len(parts) > 4 else ""
        role = principal_arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return f"arn:aws:iam::{account}:role/{role}"
    if ":role/" in principal_arn:
        return principal_arn
    return None  # user / root - undo as the base caller


def _acting_client(base: AwsClient, principal_arn: str, cache: dict) -> AwsClient:
    """Best-effort: return a client for the identity that made a mutation, so its
    undo carries the same authority. Falls back to `base` (the caller) whenever
    the acting role cannot be (re-)assumed - a deep propagation chain may need
    manual rollback as an intermediate identity, which is then reported."""
    if base is None or not principal_arn or principal_arn == base.identity.arn:
        return base
    role_arn = _role_arn_from(principal_arn)
    if role_arn is None or role_arn == base.identity.arn:
        return base
    if role_arn in cache:
        return cache[role_arn]
    try:
        acting = base.assume_role(role_arn, session_name="awspwn-rollback")
        acting.whoami()
    except Exception:  # noqa: BLE001 - cannot re-assume; undo as the caller
        acting = base
    cache[role_arn] = acting
    return acting


def apply_undo(client: AwsClient, mutation: Mutation) -> None:
    """Execute a single mutation's undo call. Raises on hard failure."""
    if not mutation.undo_api:
        raise ValueError("mutation has no undo_api (orphan) - cannot roll back")
    service, method = _service_and_method(mutation.undo_api)
    kwargs = {k: v for k, v in (mutation.undo_params or {}).items()
              if not k.startswith(_RESERVED_PREFIX)}
    region = (mutation.undo_params or {}).get("_region")
    api = getattr(client.client(service, region=region), method)
    api(**kwargs)


def rollback(
    state: State,
    client: AwsClient,
    loot_dir: Optional[str] = None,
    *,
    log: Optional[Callable[[str], None]] = None,
    dry_run: bool = False,
) -> RollbackReport:
    """Undo every un-reverted mutation on `state`, newest first.

    Persists the ledger after each successful undo (unless dry_run). Returns a
    report; never raises for an individual undo failure.
    """
    log = log or (lambda _m: None)
    report = RollbackReport()

    pending = [m for m in reversed(state.mutations) if not m.reverted]
    if not pending:
        log(_dim("  ledger is empty or already fully reverted - nothing to undo"))
        return report

    log(f"  reverting {len(pending)} mutation(s), newest first"
        + (_dim(" [dry-run]") if dry_run else ""))

    session_cache: dict = {}
    for mutation in pending:
        label = f"{mutation.api} → undo {mutation.undo_api or '(none)'}"
        if not mutation.undo_api:
            report.failed.append((mutation, "orphan mutation - no undo recorded"))
            log(f"  {_color('[skip]', C.YELLOW)} {label}: no undo recorded (orphan)")
            continue

        if dry_run:
            try:
                service, method = _service_and_method(mutation.undo_api)
                log(f"  {_color('[plan]', C.CYAN)} {service}.{method}("
                    f"{', '.join(k for k in mutation.undo_params if not k.startswith(_RESERVED_PREFIX))})")
            except ValueError as exc:
                report.failed.append((mutation, str(exc)))
            continue

        acting = _acting_client(client, mutation.principal_used, session_cache)
        try:
            apply_undo(acting, mutation)
            mutation.reverted = True
            report.reverted.append(mutation)
            save_state(state, loot_dir)
            log(f"  {_color('[ok]', C.GREEN)} {label}")
        except Exception as exc:  # noqa: BLE001
            # A vanished resource means the change is effectively already undone.
            if classify(exc) == ErrorClass.NOT_FOUND:
                mutation.reverted = True
                mutation.note = (mutation.note + " | " if mutation.note else "") + "target already gone at rollback"
                report.reverted.append(mutation)
                save_state(state, loot_dir)
                log(f"  {_color('[ok]', C.GREEN)} {label} (target already gone)")
                continue
            report.failed.append((mutation, str(exc)))
            log(f"  {_color('[fail]', C.RED)} {label}: {exc}")

    return report
