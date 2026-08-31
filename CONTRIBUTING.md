# Contributing to AWSPwn

Thanks for your interest. AWSPwn is an offensive-security tool; please read the
[Legal](README.md#legal) notice and the [Security policy](SECURITY.md) first.
Contributions are expected to preserve the "authorized use only" posture and the
safety gates.

## Development setup

```bash
git clone https://github.com/mHijuxS/awspwn && cd awspwn
uv venv && source .venv/bin/activate      # or: python -m venv .venv
uv pip install -e '.[test]'               # or: pip install -e '.[test]'
pytest                                     # offline smoke + moto
ruff check .                               # lint (F / E9 rule set)
```

## Ground rules

- **Dependencies:** boto3/botocore only (plus moto/pytest for tests). Shell out
  to `aws`/`pacu`/`cloudfox` rather than adding libraries.
- **Read-only stays read-only:** `enum`/`analyze`/`report` and the other recon
  commands must never call a mutating API (a moto test enforces this).
- **Every mutating action is undoable:** a new phase-3 strategy must record a
  `Mutation` with a concrete `undo_api`/`undo_params` (and `original_state` for
  overwrite-style APIs) so `rollback` can reverse it, and be gated by its
  `BlastRadius`.
- **No shell interpolation of untrusted values.** Executed commands run as a
  `shell=False` argv; keep it that way.
- Add a test for behavior you change, and keep `pytest` and `ruff check` green.

## Adding an attack edge

See "Adding a new edge" in [CLAUDE.md](CLAUDE.md): add the abuse entry, the enum
minting rule, and (for automation) a strategy function.

## Pull requests

Keep them focused, describe the change and its blast radius, and note any new AWS
permissions required. By contributing you agree your work is licensed under the
project's [MIT license](LICENSE).
