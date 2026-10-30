# CamCore DNS Policy

This directory contains the CamCore-owned policy, validation and publishing layer for **CamCore – Cameron Family Secure Network**.

The default production model is intentionally minimal: one approved upstream source, one generated CamCore production feed, and exact local exceptions only where required.

## Authoritative files

| Path | Purpose |
| --- | --- |
| `sources.json` | Machine-readable source manifest and production deployment state |
| `allowlist.txt` | Names CamCore must never block, grouped by service; removed from the generated feed |
| `denylist.txt` | Exact domains explicitly blocked by CamCore and added to the generated feed |
| `tools/dns_policy.py` | Shared domain syntax, allow-list matching and production size thresholds |
| `tools/publish_blocklist.py` | Builds the CamCore production feed from approved source material and local policy |
| `tools/validate_repository.py` | Offline repository and policy validator |
| `tools/check_sources.py` | Read-only check that the published feed is reachable, plausibly sized and blocks no allow-listed name |
| `tests/` | Unit tests for CamCore DNS validation and policy controls |

The generated repository-root `blocklist.txt` is a production output and must not be edited manually.

## Source states

A source entry in `sources.json` uses explicit governance states:

- `active` — approved for the deployment state recorded in the source entry;
- `under-review` — evaluation only and not production-approved; and
- `retired` — retained for history or rollback reference and not approved for current deployment.

Only a source with both `status: active` and `deployment: production` forms part of the current CamCore production baseline.

## Current baseline

The current manifest defines **HaGeZi Multi NORMAL** as the active upstream source material used to generate the CamCore production blocklist.

**StevenBlack Unified Hosts** is retained as a retired historical baseline and must not be treated as an active production source unless the manifest is deliberately changed through CamCore change control.

## Local domain-entry format

Use one entry per line:

```text
subdomain.example.net
*.example.com
```

| Entry | Allow-list | Deny-list |
| --- | --- | --- |
| `subdomain.example.net` | That exact name is never published | That exact name is added to the feed |
| `*.example.com` | `example.com` and every name beneath it are never published | Not accepted |

Entries must:

- use lower-case ASCII or valid IDNA/punycode;
- omit `http://`, `https://`, paths, ports and trailing dots;
- avoid Adblock syntax, regular expressions, IP addresses and hosts-file rows;
- remain sorted within their section;
- remain unique within the file; and
- be justified in the change record rather than with trailing inline comments.

Blank lines and full-line comments beginning with `#` are permitted and start a new section.

The allow-list must always contain the CamCore and local namespaces: `*.camcore.au`, `*.camcore.network`, `*.home.arpa`, `*.lan`, `*.local` and `*.localhost`. The validator enforces this.

The allow-list is applied after the deny-list, so an allow-listed name is never published. The validator rejects a deny-list entry that the allow-list covers.

An empty deny-list is valid and preferred when no CamCore-specific block is required.

## Change standard

A local allow or deny entry should exist only when there is a specific operational or security reason that cannot be handled more appropriately upstream.

Before a production policy change is merged:

1. establish the evidence and expected effect;
2. make the smallest policy change required;
3. run the unit tests and repository validator;
4. define the rollback path; and
5. follow the Mars-first deployment process in [`../docs/OPERATIONS.md`](../docs/OPERATIONS.md).

For upstream governance and attribution, see [`../docs/UPSTREAM.md`](../docs/UPSTREAM.md).
