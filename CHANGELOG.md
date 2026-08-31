# Changelog

All notable changes to AWSPwn are recorded here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-08-31

### Added
- Resource-derived role nodes + precise structural edges. A role referenced by a
  resource now becomes a real (minimal) `IAM_ROLE` node even with no IAM read, via
  accurate, non-abusable structural edge kinds that replace the overloaded
  `InstanceProfileFor`: `LambdaExecutionRole` (function → role), `ECSTaskRole`
  (task def → workload role) and `ECSExecutionRole` (task def → agent role, kept as
  structural metadata, never a workload identity), and `InstanceProfileRole`
  (instance profile → role, resolved via `iam:GetInstanceProfile` — never inferred
  from the profile name, and nothing is emitted when the lookup is denied). These
  structural references are not traversable pivots (absent from `roam` hops); an
  executable credential-gain pivot is minted separately only where a strategy can
  return verified credentials for that exact role.
- Existing-Lambda takeover (`LambdaTakeover`) - the first real resource-derived
  credential-gain pivot. Minted principal → the function's CURRENT execution role
  (derived from the function's own `role_arn`, so a role change reconciles the old
  edge away) only when the caller can `lambda:GetFunction` **and**
  `UpdateFunctionCode` **and** `InvokeFunction` on that specific function, and only
  for ZIP/Python runtimes (container-image and other runtimes are suppressed). The
  edge carries function ARN/name/region/runtime/handler/package-type + observed
  role ARN. The strategy backs up the original deployment package (0600 on disk),
  overwrites+invokes to capture the role's credentials, restores immediately, and
  verifies the captured identity by STS account + role name (no `GetRole`); the
  DESTRUCTIVE mutation is marked reverted only after a successful restore,
  otherwise left live so `awspwn rollback` reloads the package from disk.
  Simulation checks all three legs against the function ARN but keeps the edge
  conditional (invoke/runtime/resource controls untested). ECS/EC2 remain
  structural-only (no executable pivot) until their strategies can capture and
  verify credentials.
- Compatibility: a graph persisted before this release may retain legacy
  `InstanceProfileFor` edges that were previously (mis)used for Lambda execution
  roles and ECS task roles. They remain non-abusable, so they are harmless; a
  re-collection ADDS the precise edge kinds alongside them rather than physically
  replacing the old edges in the existing `graph.json`. Re-run `enum`/`analyze`
  (or delete the loot dir) for a graph built purely on the new kinds.
- `awspwn roam` - interactive pivot loop. From the current identity it lists the
  actionable one-hop options, executes exactly the chosen hop, and - only when
  that hop changes identity - re-collects from the new vantage before returning to
  the menu, growing the graph as it goes. Reaching admin is a checkpoint, not an
  exit; only `q` / EOF / interrupt ends the loop. Plan mode (default) previews
  each hop without pivoting; `--execute` walks them (gated by blast radius and
  recorded on the rollback ledger, like `pwn`). The graph principal id is tracked
  separately from the live STS session ARN, and the chosen edge target is the
  authoritative post-pivot id. This makes the low-IAM-read workflow usable: each
  vantage contributes only what it can see, and the picture is built by pivoting.
  In `--execute` mode it collects the initial vantage from the live credentials
  (even when the graph came from cache), refuses to run when the resolved source
  is not the caller, accepts replacement credentials for the same principal
  without a needless re-collection, offers `r` to manually re-collect the current
  vantage, and stops offering a mutating hop once it has been completed.

### Changed
- **BREAKING (Python API):** `State.account` renamed to `State.origin_account`
  to mean the engagement's *starting* account (nodes carry their own `account`,
  so a cross-account pivot grows one graph instead of resetting it). The on-disk
  JSON key stays `"account"`, so existing `state.json` / `graph.json` load
  unchanged — only direct Python constructors (`State(account=...)`) must move to
  `State(origin_account=...)`.

### Added
- Incremental, per-vantage collection foundation for the `roam` interactive
  pivot loop:
  - `aws_client.canonical_principal_id()` — maps an STS `assumed-role/ROLE/SESSION`
    session ARN back to its `role/ROLE` graph-node id (best-effort; the session
    ARN drops the IAM role path, resolved via `GetRole` when permitted).
  - `cli.collect_from()` — enumerate from a client's vantage and merge into the
    live graph + state, with union-wide correlation and accumulated (deduped)
    findings/denials.
  - Property/`conditional`-enriching merge semantics on both `AttackGraph` and
    `State`, plus adjacency-consistent `remove_edge`.
  - Principal nodes now carry a structured `grant_statements` property (normalized
    Allow/Deny statements) so correlation and future collection can evaluate
    resource-scoped permissions without the original policy documents.
  - Self-policy resolver (`IamEnumerator.resolve_self`): reads the CURRENT
    principal's own policies (user or role, incl. group inheritance) into a
    normalized `Grants`, so a vantage with no account-wide IAM read still yields a
    resource-aware self-node. **Three-state by read completeness**: `complete`
    (authoritative `grant_statements`, retraction allowed), `partial`
    (non-authoritative `grant_statements_partial`, additive-only), `none` (policy
    properties omitted). Preserves `attached_policies` and uses `GetRole`'s
    path-qualified ARN as the node id. Empirically-probed permissions are kept in
    a SEPARATE `confirmed_actions` property, never fed into policy-derived
    correlation. On GAAD denial, `enumerate()` runs piecemeal identity listing
    (when available) and then self-resolves the current principal into the same
    result, probing exactly once.
  - Correlation authority model: only an authoritative-complete snapshot of a
    principal may retract that principal's correlation edges; partial evidence and
    legacy `action_patterns` add conditional candidates but never retract or
    replace a prior complete snapshot. Piecemeal (list-only) IAM enumeration no
    longer publishes any policy-derived properties.
  - Authority-aware node merge (`models.merge_grant_properties`, used by
    `State`/`AttackGraph` add_node): permission-snapshot properties merge by
    `grant_read_status`, not last-writer-wins. A later partial read can never
    downgrade, overwrite, or make inconsistent a prior complete snapshot; a
    complete read supersedes and clears partial evidence; a `none` read preserves
    prior knowledge. Partial display data lives in separate `*_partial` keys.
    Tradeoff: a newer partial observation cannot augment an older complete
    snapshot, so a permission change seen only by a partial read stays undiscovered
    until the next complete read of that principal.
  - Privesc `CreatePolicyVersion`/`SetDefaultPolicyVersion` edges are now minted
    per attached customer-managed policy (checked against that policy's ARN), so
    the edge exists only for a policy the principal holds and the strategy has a
    concrete target to rewrite.

### Fixed
- `iam:SimulatePrincipalPolicy` is now wired in (the module existed but was unused):
  `collect_from` opportunistically refines the CURRENT vantage's candidate edges
  through AWS's evaluator. It is three-valued - `allowed` / `explicitDeny` /
  `indeterminate` (implicit deny, missing condition context, and unsupported combos
  are indeterminate, never collapsed to a definite deny), plus `unavailable` when
  the permission is absent (probed via the request itself, no separate check).
  Because simulate evaluates only the IDENTITY policy (not resource policies, and
  none for role targets), an `allowed` clears an edge's `conditional` ONLY for
  identity-governed edges (IAM privesc); for resource access (S3/KMS/Secrets/
  Lambda) and any sts:AssumeRole leg it records `simulated_identity="allowed"` as
  evidence but keeps `conditional`. A conclusive explicit deny retracts an offline
  candidate (independently-observed edges preserved). Each composite edge action
  is evaluated against its own action-specific resource (no cross-product), using
  the path-qualified IAM principal ARN as `PolicySourceArn`. The evidence property
  never replaces the existing `via` provenance, and upgrades/removals apply to the
  State ledger and the AttackGraph together. Bounded per pass by a deduplicated
  unique-request budget (conditional/privesc edges first; truncation logged).
  No-op under moto / without the permission.
- `PwnEngine.context()` now prefers the live identity's account over the engine's
  origin account, so command templates target the correct account after a
  cross-account pivot.
- `Grants` policy evaluation, previously a flat Allow-only matcher, is now a
  three-valued evaluator:
  - `NotAction` is the **complement** ("everything except"), no longer unioned
    into `Action` (which falsely reported the excluded actions as allowed).
  - Explicit **Deny** precedence, gated on action + resource + evaluable
    condition; unevaluable conditions yield conditional/unknown, never a definite
    allow or deny.
  - **Resource/NotResource** wildcard matching, case-sensitive (actions stay
    case-insensitive), with a resource-aware `allows_action(action, resource)`
    for edge decisions and `allows_action_anywhere(action)` for discovery.
  - `is_admin` now means literal **unrestricted** admin: a genuinely-universal
    unconditional `Allow` with no Deny of any kind (was: trusted a bare
    `Allow "*"`, and accepted `Allow NotAction`).
- Correlation evaluates a principal's structured grants against the
  **action-specific** resource ARN (honouring scoping/denies) instead of the flat
  `action_patterns` list, which over-claimed. Pattern-only (older) graphs fall
  back to a resource-blind match, marked `conditional`.
- Correlation now **reconciles** rather than only adding: across incremental
  collections it upgrades a legacy conditional edge once structured grants confirm
  it, and **retracts** a correlation edge that newer permissions deny (removal
  synchronized across `State` and `AttackGraph`, and only for
  `via="correlation"` edges — independent provenance is preserved). An empty
  `grant_statements` set is authoritative and suppresses the pattern fallback.
- Privesc edges are now **target-aware**: a grant scoped to another principal no
  longer mints a self-escalation edge; per-action resources distinguish the
  escalation target from out-of-scope gate actions.

## [0.1.0]

- Initial public release.
