# CamCore DNS Security Policy

This policy applies to the CamCore-owned DNS policy, tooling, automation and documentation in `Team-CamCore/dns-blocklists`.

## Reporting a security issue

Do **not** open a public GitHub issue containing sensitive information.

Report a vulnerability affecting CamCore-owned policy, publishing logic, validation tooling or repository automation through:

- **CamCore Support:** https://camcore.au/support
- **Email:** `help@camcore.au`

Include a clear description, the affected file or workflow, reproduction steps where safe, expected impact and any proposed mitigation.

Never include passwords, access tokens, API keys, private keys, resolver exports, DNS query logs, browsing information, client details, private infrastructure inventories or other sensitive operational data.

## Scope

CamCore maintains:

- files under `camcore/`;
- the generated CamCore production feed at `blocklist.txt`;
- CamCore documentation under `docs/`;
- CamCore-named GitHub Actions workflows;
- repository-level CamCore documentation and governance files; and
- the CamCore-specific processing applied to approved upstream source material.

HaGeZi retains responsibility for its upstream source material. Confirm suspected upstream data defects and report them through the upstream project's published process where appropriate.

## DNS false positives

A false positive is normally an operational filtering issue rather than a software vulnerability.

Before requesting a policy change:

1. confirm DNS filtering is the cause;
2. identify the smallest exact domain involved;
3. avoid publishing private query logs or client details; and
4. submit non-sensitive evidence through CamCore Support.

CamCore will prefer the narrowest safe exception and will consider whether the correction belongs upstream before adding a permanent local allow-list entry.

## Supply-chain and workflow concerns

Security reports are especially relevant when they involve:

- unexpected modification of `blocklist.txt`;
- bypass of repository validation;
- unsafe GitHub Actions permissions;
- untrusted or unpinned workflow dependencies;
- source-integrity failures;
- publication of malformed or unvalidated data; or
- exposure of sensitive CamCore operational information.

The production publishing workflow is intentionally the only write-capable workflow on the default branch.

## Supported version

Only the current `main` branch is maintained as the approved CamCore repository state.

The `upstream-hagezi` branch is retained for provenance and controlled reference and is not an approved CamCore deployment branch.
