# AWSPwn - AWS attack-path automation

Enumerate an account's IAM and resources into a graph, find privilege-escalation
and lateral-movement paths, and auto-execute the chain with credential
propagation between hops - BloodHound-style attack-path automation, applied to
the cloud.

There is no existing tool that does the whole chain for AWS: CloudFox does recon,
enumerate-iam probes permissions, PMapper graphs IAM (unmaintained since 2022),
Pacu runs individual exploit modules. AWSPwn stitches
*enumerate → graph → find path → exploit* into one workflow.

> ⚠️ **Authorized use only.** AWSPwn automates real, billable, CloudTrail-logged
> actions against AWS accounts, including privilege escalation and persistence.
> Use it only against accounts you own or are explicitly authorized to test. See
> [Legal](#legal).

> **Status:** phases 1+2 (read-only recon + attack-path analysis) and phase 3
> (exploitation - `pwn` / `console` / `rollback`) are complete. `pwn` walks a
> path in-process with credential propagation, gates every mutating hop by blast
> radius, and records a `Mutation` ledger that `rollback` replays LIFO.

---

## Install

```bash
git clone https://github.com/mHijuxS/awspwn && cd awspwn
uv tool install . --force --no-cache      # or: uv pip install -e '.[test]' in a venv
awspwn --help
```

Requires Python ≥3.10 and `boto3`/`botocore` (the only third-party dependencies -
signing SigV4 and paginating by hand is not worth it). Everything else is
stdlib. The core paths (`enum`/`analyze`/`pwn`) run boto3 in-process and need no
external tools; the `aws` CLI is what the printed runbook commands use, and
`awspwn exploit --execute` will invoke `aws` automatically for the simple
fallback steps it runs on your behalf.

## Credentials

Standard boto3 resolution. **Prefer a named profile or environment variables.**
Passing `--access-key`/`--secret-key` on the command line leaks them into your
shell history and the process list (other local users can read them via `ps`):

```bash
awspwn enum --profile dev                          # recommended
AWS_PROFILE=dev awspwn enum                         # or export AWS_ACCESS_KEY_ID/...
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # [AWS_SESSION_TOKEN=...]

awspwn enum --access-key AKIA... --secret-key ...  # convenient, but leaks creds (see warning)
```

## Commands

| Command | What it does |
|---|---|
| `awspwn enum` | Enumerate identities + resources into `graph.json` / `state.json` |
| `awspwn analyze` | Enumerate, then print every path from the caller to admin |
| `awspwn whoami` | Resolve the current caller identity |
| `awspwn load <graph.json>` | Load a saved graph, print stats + high-value targets |
| `awspwn path <src> <dst>` | Find attack path(s) between two nodes (`--all-paths`) |
| `awspwn reachable <src>` | BFS reachability map from a node |
| `awspwn info <edge>` | Abuse details + commands for one edge type |
| `awspwn edges` | List all abusable edge types by category |
| `awspwn exploit [src] [dst]` | Choose a path, print its filled-in runbook; `--execute` walks identity hops (boto3) + prompts before mutations |
| `awspwn report [--format json]` | Render a report from saved state |
| `awspwn loot [--show-secrets] [--export NAME]` | Summarize state + captured creds; `--show-secrets` prints them; `--export NAME` emits eval-able lines for one cred: `eval "$(awspwn loot --export NAME)"` |
| `awspwn pwn [src] [dst]` | Automated walk with credential propagation; plan by default, `--execute` to run, `--allow-destructive/-external/-orphan` gates, `--rollback-on-failure` |
| `awspwn console` | Trade the current CLI creds for a console sign-in URL (federation) |
| `awspwn rollback` | Replay the mutation ledger LIFO to undo a `pwn` run (`--dry-run`, `-y`) |

Common flags: `--profile --region --access-key/--secret-key/--session-token
--loot-dir --data --max-depth --no-color -v`. `pwn`/`path`/`reachable`/`exploit`
reuse the saved `<loot-dir>/graph.json` if present; pass `--no-cache` (alias
`--fresh`) to ignore it and re-enumerate from AWS.

### Typical flow

```bash
awspwn enum --profile dev                       # build the graph
awspwn analyze --profile dev                    # caller -> admin paths + findings
awspwn path 'arn:aws:iam::111:user/dev' admin --all-paths
awspwn exploit --profile dev                    # pick a path -> get its exact commands
awspwn exploit --profile dev --execute          # ...and walk the identity hops for you
awspwn info CreateAccessKey                     # how to abuse a specific edge
```

`exploit` is the interactive bridge to phase 3: it lists the discovered paths,
you pick one, and it prints a concrete runbook with the real ARNs filled in.
With `--execute` it assumes each role in-process (boto3 - real credential
propagation between hops) and prompts before any mutating step; steps that need
out-of-band scaffolding (a Lambda zip, a user-data script) are flagged
`[manual]` rather than guessed at.

Node lookup accepts a full ARN, a name, or an ARN suffix (`dev` resolves
`arn:aws:iam::111:user/dev`). The synthetic goal node is named `admin`.

---

## The graph model

A **principal-centric hybrid graph** (PMapper's model + resource nodes). An edge
`A --[Kind]--> B` means *"holding identity A, I can perform an action that yields
B's credentials/privileges or B's data."*

| ADPwn | AWSPwn | Meaning |
|---|---|---|
| `ForceChangePassword` | `CanAssume` | become the target (identity change) |
| `ReadLAPSPassword` | `GetSecretValue` | yields creds *if* the secret holds them |
| `AdminTo` → dump | `SSMSendCommand` → `IMDSCredentialTheft` | code-exec on host → steal its role |
| `GenericAll` | `AttachUserPolicy` / `CreatePolicyVersion` | mutate target so you gain its privilege |

### 67 abusable edge types across five modules

- **`edges/iam.py`** - the canonical Rhino privesc set: `CreateAccessKey`,
  `AttachUserPolicy`, `PutUserPolicy`, `CreatePolicyVersion`,
  `UpdateAssumeRolePolicy`, `AddUserToGroup`, `CanAssume`, `PassRole`, …
- **`edges/compute.py`** - PassRole + EC2/SSM/IMDS/Lambda/ECS/EKS/Glue/CFN/
  SageMaker/CodeBuild.
- **`edges/data.py`** - S3, Secrets Manager, SSM Parameter Store, KMS, DynamoDB,
  EBS/RDS snapshots, ECR, CloudWatch Logs.
- **`edges/persist.py`** - access keys, login profiles, role-trust backdoors,
  instance-profile swaps, Lambda resource-policy backdoors, federation tokens.
- **`edges/org.py`** - resource-policy sharing to external accounts, cross-account
  assumption, Organizations abuse, SCP weakening, IAM Identity Center.

Each edge carries a **blast radius** (`READ` / `MUTATE` / `DESTRUCTIVE` /
`EXTERNAL_EXPOSURE`) that both gates execution (phase 3) and adds a pathfinding
surcharge - so `analyze` prefers the *quietest* route to admin, not merely the
shortest.

---

## How enumeration degrades

You rarely have full IAM read on a real engagement, so `enum/iam.py` steps down:

1. `iam:GetAccountAuthorizationDetails` - one-shot dump of everything.
2. denied → individual `List*`/`Get*` per object type.
3. denied → **enumerate-iam brute force**: probe a curated list of read-only,
   safe-argument API calls to map the *current identity's* effective permissions
   with zero IAM read privilege.

Effective permissions are computed by a fast, offline policy matcher over the raw
`Allow` statements (works under moto and offline). It does **not** model deny
statements or most `Condition` keys - such edges are marked `conditional`.
`policy/simulate.py` refines them authoritatively via
`iam:SimulatePrincipalPolicy` when the caller holds it.

---

## Safety

Phases 1+2 are strictly read-only: `enum`/`analyze`/`report` never call a
mutating API (asserted by a moto test). Phase 3 (`pwn`) is gated:

- **plan by default** - `pwn` prints a per-hop execution plan and changes
  nothing; `--execute` is required before any mutating call runs;
- **blast-radius gates** (`strategy.Gates.permits`, checked *before* the boto3
  call) - a `MUTATE` hop needs `--execute`; `DESTRUCTIVE` also needs
  `--allow-destructive`; `EXTERNAL_EXPOSURE` also needs `--allow-external`; a
  mutating hop whose undo cannot be recorded needs `--allow-orphan`;
- **rollback ledger** - every mutating call is written to a `Mutation` in
  `state.json` with a concrete undo (`undo_api` + `undo_params`, plus
  `original_state` for overwrite-style APIs like `UpdateAssumeRolePolicy`);
  `awspwn rollback` replays them LIFO and is idempotent (`--rollback-on-failure`
  undoes automatically when a run stalls short of the goal);
- **no guessing** - scaffolding-heavy edges (RunInstanceWithRole, ECS/Glue/CFN,
  cross-account sharing) are rendered as a manual runbook rather than executed;
- the ledger stores only API calls and their undo params; captured credential
  material is never written to `state.json`;
- **captured/created credentials are persisted** to a separate owner-only
  (`0600`) `captured-creds.jsonl` in the loot dir - a minted access key, a
  Lambda-captured role session, or an access key found inside a secret. They are
  written the moment they are obtained, so a hop failing later never orphans a
  key whose secret you would otherwise lose; and `pwn` **reuses** them on a
  re-run (validating first), so a retry does not re-mint a duplicate or trip the
  2-keys-per-user cap. Inspect them with `awspwn loot` (`--show-secrets` to
  print the values); **become one** with `eval "$(awspwn loot --export NAME)"`.
  Each entry is tagged with its account and flagged if it is a session/ephemeral
  credential or belongs to a different account than the current graph (e.g. a
  previous lab), and `enum` starts a fresh graph rather than merging when the
  account changes - so a stale credential from a torn-down account is obvious
  instead of silently failing to authenticate.

---

## Testing

```bash
uv pip install -e '.[test]'
pytest                       # offline smoke + moto-backed enum/pathfinding
```

- **Offline smoke** (`tests/test_smoke.py`) - models/graph/abuse/edge-DB and
  pathfinding over `tests/fixtures/sample_graph.json`. No AWS, no network.
- **moto enum** (`tests/test_enum_moto.py`) - seeds a vulnerable IAM layout, runs
  the real enumerators, asserts the path is found, the degradation chain fires,
  and read-only enumeration mutates nothing.
- **moto exploitation** (`tests/test_pwn_moto.py`) - drives the phase-3 engine:
  credential propagation, the mutation ledger, LIFO rollback, blast-radius gates,
  and secret-credential capture.

> **Maturity note.** The read-only phases (`enum`/`analyze`/…) call only read
> APIs and are safe to run anywhere. The exploitation engine's core path -
> `CreateAccessKey` credential propagation, `CreateLambdaWithRole` credential
> capture, the mutation ledger, and reaching admin - has been validated
> end-to-end against a real (CloudGoat-style) AWS account, in addition to the
> [moto](https://github.com/getmoto/moto) unit tests. Less common strategies
> (SSM, ECS/Glue/CFN and other compute PassRole chains) render a manual runbook
> rather than executing in-process and are not each individually exercised;
> `--execute`'s plan output shows which hops run and which are manual. Still,
> validate `pwn --execute` in a throwaway account before relying on it on an
> engagement. Note that a create-not-delete caller cannot undo its own
> artifacts; `--cleanup` rolls back using the elevated identity you reach.

For a live end-to-end run, [BishopFox/iam-vulnerable](https://github.com/BishopFox/iam-vulnerable)
provisions ~30 real privesc paths with Terraform: `terraform apply` →
`awspwn enum` → `awspwn analyze` should surface each planted path. (Costs money;
not automated.)

---

## Legal

For **authorized security testing only.** AWSPwn is built for engagements you have
explicit written permission to conduct. Every mutating action is logged in
CloudTrail and attributable to your credentials - this is by design. You are
responsible for how you use it, and for cleaning up (the `rollback` ledger and
`--rollback-on-failure` exist to help). The authors accept no liability for
misuse or damage.

## License

MIT - see [LICENSE](LICENSE).
