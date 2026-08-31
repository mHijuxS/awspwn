# AWSPwn - AWS Attack Path Automation

BloodHound-style AD attack-path automation, applied to AWS: enumerates IAM +
resources into a graph, finds privesc/lateral paths, and (phase 3) auto-executes
chains with credential propagation. Phases 1+2 (read-only recon + path analysis)
and phase 3 (exploitation: `pwn`/`console`/`rollback`) are implemented.

## Dependencies

**`boto3` and `botocore` are the only third-party libraries** (+ `moto`/`pytest`
as test extras); everything else is stdlib. Rationale: AWS auth is SigV4 + STS
credential chains + pagination + typed error codes - hand-rolling that over
urllib is a large, fragile surface with no upside. Keep the dep list lean; shell
out to `aws`/`pacu`/`cloudfox` rather than adding libraries.

## Project structure

```
src/awspwn/
├── cli.py          # argparse dispatcher (set_defaults(func=) + int codes);
│                   #   boto3 commands lazy-import the AWS layer so offline
│                   #   commands (edges/info/load/path/report) need no boto3
├── models.py       # NodeKind, Node, Edge, AttackPath, AbuseStep, AbuseInfo,
│                   #   AwsIdentity, BlastRadius, Mutation, Severity, Finding
├── graph.py        # AttackGraph: Dijkstra/DFS/BFS + blast-radius edge cost
├── colors.py       # C/_color/_bold/disable_color/banner (ANSI helpers)
├── aws_client.py   # kerberos.py analogue: session factory, region iteration,
│                   #   retry_until_consistent, ClientError classification
├── abuse.py        # merge edge DBs -> MASTER_ABUSE_DB, format_command
├── state.py        # State + Mutation ledger persisted to <loot>/state.json,
│                   #   plus graph.json for `awspwn load`
├── report.py       # terminal (severity-grouped) / json / loot / paths / edges
├── exploit.py      # interactive path walker (runbook render + boto3 walk) -
│                   #   the smaller bridge; `pwn` supersedes it, reusing its
│                   #   _handle_create_lambda / assume-role primitives
├── strategy.py     # phase-3 core: PwnEngine.walk + per-edge PwnStrategy
│                   #   registry (STRATEGIES) + Gates + StepResult; in-process
│                   #   boto3 execution, credential propagation, fallback chain
├── rollback.py     # LIFO replay of state.mutations; undo_api -> boto3 method
│                   #   via botocore.xform_name; idempotent, NOT_FOUND-tolerant
├── console.py      # federation sign-in URL (stdlib urllib); GetFederationToken
│                   #   for long-term IAM-user creds, direct for session creds
├── enum/           # ServiceEnumerator + ThreadPoolExecutor fan-out
│   ├── base.py     #   run_all(); AccessDenied recorded, never fatal
│   ├── iam.py      #   GAAD -> per-call -> enumerate-iam brute force; mints
│   │               #   CanAssume / MemberOf / privesc edges (offline matcher)
│   ├── sts.py  s3.py  ec2.py  lambda_fn.py  secrets.py  rds.py  dynamodb.py
│   ├── compute_extra.py  org.py
│   └── correlate.py#   post-pass: principal action_patterns × resource nodes
│                   #   -> GetSecretValue / ReadS3Object / SSMSendCommand / ...
├── policy/
│   └── simulate.py #   iam:SimulatePrincipalPolicy (authoritative, opportunistic)
└── edges/          # abuse DBs (67 abusable edge kinds); __init__.py empty
    ├── iam.py      #   Rhino privesc set + identity/structural
    ├── compute.py  #   PassRole + EC2/SSM/IMDS/Lambda/ECS/EKS/Glue/CFN/...
    ├── data.py     #   S3/Secrets/SSM-param/KMS/DynamoDB/snapshots/ECR/logs
    ├── persist.py  #   keys/login-profile/trust-backdoor/lambda-perm/...
    └── org.py      #   external resource sharing / cross-account / SCP / SSO
```

## Key design patterns

- **Placeholders**: `{PRINCIPAL_ARN}`, `{TARGET_ARN}`, `{ROLE_NAME}`, `{BUCKET}`,
  `{SECRET_ID}`, … plus the meta-placeholder `{AWS_AUTH}` (the `{IMPACKET_AUTH}`
  analogue) that expands to `--profile X --region Y` vs env-injected creds.
  `format_command` is a deliberate `str.replace` loop (NOT `str.format`) so the
  literal JSON braces in `aws` CLI commands survive.
- **Graph semantics**: edge `A --[Kind]--> B` = "as A, I can act to gain B's
  privileges/creds/data". Self-escalation edges point at a synthetic per-account
  `admin` goal node (name "admin", `synthetic_goal=True`, excluded from HVTs).
- **Blast radius**: every `AbuseStep`/`AbuseInfo` carries `BlastRadius`
  (READ/MUTATE/DESTRUCTIVE/EXTERNAL_EXPOSURE). It (1) adds a pathfinding
  surcharge in `graph._edge_cost` so `analyze` prefers the quietest route, and
  (2) gates execution in phase 3.
- **Degradation chain** (enum/iam.py): GAAD → per-object List/Get →
  enumerate-iam brute-force probes. AccessDenied is intel, recorded as a finding.
- **Effective permissions**: offline `Grants` matcher over raw Allow statements
  (deny/conditions NOT modelled → edges flagged `conditional`); simulate.py
  refines via `iam:SimulatePrincipalPolicy` when available. moto lacks Simulate,
  so tests rely on the offline matcher.
- **Safety**: phases 1+2 never call a mutating API (asserted by a moto test).
  Phase 3 gates every mutating hop by `BlastRadius` in `strategy.Gates.permits`:
  `--execute` to mutate at all (default is a plan/dry-run), `--allow-destructive`
  for DESTRUCTIVE, `--allow-external` for EXTERNAL_EXPOSURE, `--allow-orphan` for
  a mutating step whose undo cannot be recorded. Every mutating call is written
  to the `Mutation` ledger with a concrete undo; `awspwn rollback` replays it
  LIFO. Scaffolding-heavy edges (RunInstanceWithRole, ECS/Glue/CFN/…) fall back
  to a rendered manual runbook rather than guessing at out-of-band setup.

## Adding a new edge

1. Add an `AbuseInfo` to the right `edges/*.py` `ABUSE_DB` with `linux_steps`,
   `blast_radius`, `required_permissions`, `opsec_considerations`.
2. If it should be minted during enum, add a rule to `_PRIVESC_RULES`
   (enum/iam.py) for principal-privesc, or `_RESOURCE_RULES` (enum/correlate.py)
   for principal→resource access.
3. If it is a graph-topology-only edge, add it to `_STRUCTURAL` in abuse.py.
4. For automation (phase 3): add a strategy function
   `(engine, client, edge, src, dst, ctx) -> StepResult` and register it in
   `strategy.py`'s `STRATEGIES` dict. Record any mutating call via
   `engine.record_mutation(...)` with a concrete `undo_api`/`undo_params` (and
   `original_state` for overwrite-style APIs) so `rollback` can undo it. Edges
   with no in-process strategy fall through to `_strat_default` (rendered manual
   steps). Identity-changing strategies return a new `AwsClient` in
   `StepResult.new_client` to propagate credentials to the next hop.

## Conventions

- Every edge module exports one `ABUSE_DB: dict[str, AbuseInfo]`; abuse.py merges.
- Enumerators subclass `ServiceEnumerator`, set `name`/`service`/`is_global`,
  return `EnumResult(nodes, edges, findings, denied)`, and swallow AccessDenied
  via `self._handle`.
- ANSI via `C`/`_color`/`_bold` in colors.py; colors auto-off when not a TTY.
- Node `object_id` is the ARN wherever one exists.

## Build & test

```bash
uv tool install . --force --no-cache          # house install pattern
uv pip install -e '.[test]' && pytest         # offline smoke + moto enum tests
```

No commits unless the user explicitly asks.
