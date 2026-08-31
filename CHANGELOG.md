# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-30

Initial public release.

### Added
- **Recon (phases 1-2):** enumerate IAM + resources into an attack graph, with
  `enum`, `analyze`, `path`, `reachable`, `load`, `report`, `loot`, `info`,
  `edges`, `whoami`, and the interactive `exploit` runbook walker.
- **Exploitation (phase 3):** `pwn` walks a path in-process with credential
  propagation, gated per hop by blast radius and recording a `Mutation` ledger;
  `rollback` replays that ledger LIFO; `console` mints a federation sign-in URL.
- `pwn --cleanup`: after the walk, roll back the mutation ledger using the gained
  (elevated) identity, so a create-not-delete caller can still remove its own
  artifacts once it has escalated.
- `--no-cache` (alias `--fresh`): make `pwn`/`path`/`reachable`/`exploit` ignore
  the saved `<loot-dir>/graph.json` and re-enumerate live from AWS.
- **Captured-credential store** (`captured-creds.jsonl`, `0600`): every created
  or captured credential (minted access key, Lambda-captured role session,
  access key found in a secret) is persisted the moment it is obtained and
  surfaced in the run summary, so a later hop failing never orphans a key whose
  secret would be lost. `pwn` reuses a stored credential on a re-run (after
  validating it), avoiding duplicate keys and the 2-keys-per-user cap.
  `awspwn loot [--show-secrets]` inspects the store, and
  `eval "$(awspwn loot --export NAME)"` loads a captured identity into the shell
  (clean `export` lines to stdout, info to stderr). Captured creds are tagged by
  account and flagged as session/ephemeral or cross-account, and `enum` starts a
  fresh graph instead of merging when the account changes (e.g. a relaunched
  lab), so a stale credential from a torn-down account is obvious.
- 67 abusable edge types; an offline effective-permission matcher with optional
  `iam:SimulatePrincipalPolicy` refinement.
- Test suite: offline smoke + moto-backed enum / exploitation / rollback.
- MIT license, SECURITY policy, and CI (test / lint / build / secret-scan across
  Python 3.10-3.13).

### Security
- The loot directory is created `0700` and all state / graph / report files are
  written `0600`, regardless of the process umask.
- Rendered fallback commands execute via a `shell=False` argv, so graph-derived
  node names and ARNs cannot inject shell syntax.

### Validation
- Validated end-to-end against a real CloudGoat-style AWS lab
  (`CreateAccessKey` -> `CreateLambdaWithRole` -> admin), which surfaced and
  fixed two real-AWS-only issues that moto masks: the Lambda Pending-state race
  (invoke now retries until the function is Active), and cleaning up the helper
  function as the captured role when the creating principal lacks
  `DeleteFunction`. Helper function names are now unique per run to avoid
  collisions.

[Unreleased]: https://github.com/mHijuxS/awspwn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mHijuxS/awspwn/releases/tag/v0.1.0
