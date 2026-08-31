# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** - do not open a public
issue.

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and click **"Report a vulnerability"** (GitHub Security Advisories). That
opens a private channel with the maintainers.

Include, where you can: the affected version or commit, a description, steps to
reproduce or a proof of concept, and the impact. We aim to acknowledge reports
within a few days.

## Supported versions

AWSPwn is pre-1.0. Only the latest release (and `main`) receives security fixes.

| Version                        | Supported |
| ------------------------------ | --------- |
| latest release / `main`        | ✅        |
| anything older                 | ❌        |

## Scope: what is and isn't a vulnerability

AWSPwn is an **offensive security tool**. By design it performs privilege
escalation, credential capture, and persistence against AWS accounts you point
it at. That an operator can use it to attack an account they have access to is
expected behavior, **not** a vulnerability, and is covered by the [authorized-use
policy](README.md#legal).

In scope (please report):

- Command or code injection reachable through tool input (for example a crafted
  `graph.json` achieving shell execution on the operator's host).
- Loot / state written with overly permissive file or directory permissions.
- The tool leaking its own credentials or captured secrets to unintended places
  (logs, world-readable files, network).
- AWSPwn taking a mutating action outside the operator's stated intent or its
  documented safety gates.

Out of scope:

- Using AWSPwn against a target you are not authorized to test.
- The documented, gated exploitation behavior itself.
