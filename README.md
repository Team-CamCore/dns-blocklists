<!-- CAMCORE-REPOSITORY-BRANDING:START -->
<p align="center">
  <a href="https://camcore.au">
    <img src=".github/brand/camcore-repository-banner.svg" alt="CamCore" width="520">
  </a>
</p>
<!-- CAMCORE-REPOSITORY-BRANDING:END -->

# CamCore DNS Blocklists

[![Validate CamCore DNS policy](https://github.com/Team-CamCore/dns-blocklists/actions/workflows/camcore-validate.yml/badge.svg)](https://github.com/Team-CamCore/dns-blocklists/actions/workflows/camcore-validate.yml)
[![Publish CamCore DNS blocklist](https://github.com/Team-CamCore/dns-blocklists/actions/workflows/camcore-publish.yml/badge.svg)](https://github.com/Team-CamCore/dns-blocklists/actions/workflows/camcore-publish.yml)
[![Source health](https://github.com/Team-CamCore/dns-blocklists/actions/workflows/camcore-source-health.yml/badge.svg)](https://github.com/Team-CamCore/dns-blocklists/actions/workflows/camcore-source-health.yml)
[![Licence: GPL-3.0](https://img.shields.io/badge/licence-GPL--3.0-blue.svg)](LICENSE)

Production DNS filtering policy, controlled publishing and upstream-source governance for **CamCore – Cameron Family Secure Network**.

> **CamCore is a privately owned and operated family technology network that delivers secure, reliable and professionally managed digital services for the Cameron household, Cameron-Media and associated family operations.**

**Built for Home. Engineered Like Enterprise.**

---

## Production feed

CamCore-managed Pi-hole resolvers use one stable CamCore-owned feed:

```text
https://raw.githubusercontent.com/Team-CamCore/dns-blocklists/main/blocklist.txt
```

The production feed is generated from **HaGeZi Multi NORMAL** and processed through CamCore policy before publication.

Do **not** subscribe CamCore resolvers directly to the upstream HaGeZi source in addition to this URL. The CamCore feed already incorporates the approved upstream data and local policy.

## Operating model

CamCore deliberately keeps DNS filtering simple and controlled. This is the **minimal** CamCore DNS filtering baseline: one approved upstream source, one published production feed and only evidenced local exceptions.

1. **One approved upstream baseline** — HaGeZi Multi NORMAL.
2. **One CamCore production URL** — `blocklist.txt` in this repository.
3. **One local allow-list** — explicit CamCore exceptions that must be removed from the upstream data.
4. **One local deny-list** — exact CamCore additions that must be included in the published feed.
5. **One validation and publishing pipeline** — failed generation never replaces the last-known-good production list.
6. **One staged deployment model** — validate on one resolver before applying the same change to the second resolver.

A larger number of blocklists is not considered an improvement by itself. CamCore favours predictable behaviour, low false-positive risk, traceable changes and simple rollback.

## How the feed is built

```text
HaGeZi Multi NORMAL
        │
        ▼
Validate upstream data
        │
        ▼
Remove camcore/allowlist.txt
        │
        ▼
Add camcore/denylist.txt
        │
        ▼
Normalise • deduplicate • sort
        │
        ▼
Validate final output
        │
        ▼
blocklist.txt
        │
        ▼
CamCore Pi-hole resolvers
```

The publisher rejects malformed or unexpectedly small upstream data, protects CamCore-owned and local resolver namespaces from accidental publication, and updates `blocklist.txt` only after a successful build.

If generation fails, the existing production feed remains untouched.

## Current production standard

| Component | State | Production role |
| --- | --- | --- |
| **CamCore DNS Blocklist** | Active | Single approved Pi-hole production feed |
| **HaGeZi Multi NORMAL** | Active upstream | Approved source material for the CamCore feed |
| **CamCore allow-list** | Active | Removes approved local exceptions from the generated feed |
| **CamCore deny-list** | Active | Adds approved exact-domain blocks to the generated feed |
| **StevenBlack Unified Hosts** | Retired | Previous baseline retained for history and rollback reference |
| **Additional third-party lists** | Not approved | Require evidence, testing and change control before production use |

The machine-readable source of truth is [`camcore/sources.json`](camcore/sources.json).

## Repository map

| Path or branch | Purpose | Authority |
| --- | --- | --- |
| [`blocklist.txt`](blocklist.txt) | Stable Pi-hole production feed | Generated production consumable |
| [`camcore/sources.json`](camcore/sources.json) | Approved source manifest and deployment state | Authoritative policy |
| [`camcore/allowlist.txt`](camcore/allowlist.txt) | Exact domains explicitly allowed by CamCore | Authoritative local policy |
| [`camcore/denylist.txt`](camcore/denylist.txt) | Exact domains explicitly denied by CamCore | Authoritative local policy |
| [`camcore/tools/`](camcore/tools) | Validation, publishing and source-health tooling | CamCore automation |
| [`camcore/tests/`](camcore/tests) | Repository policy and validator tests | CamCore validation |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Deployment, verification and rollback procedures | Operational standard |
| [`docs/UPSTREAM.md`](docs/UPSTREAM.md) | Upstream governance and provenance | Governance standard |
| [`docs/REPOSITORY-SETTINGS.md`](docs/REPOSITORY-SETTINGS.md) | Required GitHub repository controls | Repository standard |
| `.github/workflows/camcore-*` | Validation, publication and health automation | Approved GitHub Actions |
| `upstream-hagezi` | Preserved upstream fork snapshot | Provenance and controlled reference only |

`blocklist.txt` is generated. **Do not edit it manually.**

The `upstream-hagezi` branch is not a deployment branch and must not be merged into `main`.

## Automation and controls

### Validate CamCore DNS policy

Runs on pushes to `main`, pull requests targeting `main`, and manual dispatch.

It runs the CamCore unit tests and repository validator to confirm that policy files, local domain entries and repository structure meet the approved standard.

### Publish CamCore DNS blocklist

Runs when production policy or publishing logic changes, can be started manually, and refreshes daily.

This is the only intentionally write-capable workflow on `main`. Its write permission is limited to repository contents so it can replace `blocklist.txt` after a successful build.

### Check CamCore DNS source health

Runs after a successful publication, on its scheduled health check and by manual dispatch.

It validates repository policy and confirms that the published CamCore production feed remains reachable and plausible.

## Resolver deployment standard

Production changes are deployed **one resolver at a time**.

1. Confirm both resolvers are healthy before the change.
2. Confirm the replication mechanism and pause automatic configuration sync before staging. Also prevent automatic gravity refreshes from consuming an unvalidated mutable feed on both resolvers.
3. Apply a pinned candidate feed or configuration to the secondary resolver first.
3. Rebuild Pi-hole Gravity.
4. Query the staged resolver directly.
5. Validate general internet access and the intended block or allow behaviour.
6. Validate Microsoft 365, NetBird, CamCore public services, CamCore private services and commonly used household applications.
7. Apply the same change to the primary resolver only after the first-stage checks pass.
8. Record any significant production change in CamCore Operations.

The full procedure and rollback requirements are documented in [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Change control

Every production DNS change must be deliberate and reversible.

A change should:

- state the reason and supporting evidence;
- identify the exact source or domain entry affected;
- assess likely impact and false-positive risk;
- pass repository validation and tests;
- publish successfully before resolver rollout;
- be staged on one resolver first;
- include a defined rollback path; and
- be recorded in CamCore Operations when operationally significant.

For local exceptions, prefer the smallest exact domain required. Broad parent-domain exceptions should be treated as exceptional changes and reviewed accordingly.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for repository contribution requirements.

## Upstream relationship

This repository originated as a fork of [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists).

HaGeZi and its contributors retain authorship of their upstream material. CamCore does not claim authorship of HaGeZi content. CamCore's production feed applies CamCore-owned policy and publishing controls to the approved HaGeZi Multi NORMAL source.

The inherited upstream snapshot is retained on `upstream-hagezi` for provenance and controlled reference only. CamCore does not blindly synchronise upstream repository automation or generated content into `main`.

See [`NOTICE.md`](NOTICE.md) and [`docs/UPSTREAM.md`](docs/UPSTREAM.md) for attribution and governance details.

## Security and privacy

This repository is public. Never commit or publish:

- credentials, API keys, tokens or private keys;
- resolver exports or backups;
- DNS query logs or browsing history;
- client or household-identifying data;
- private infrastructure inventories; or
- other sensitive operational information.

Security reporting instructions are available in [`SECURITY.md`](SECURITY.md).

## Support

For a CamCore DNS filtering issue, false positive or approved change request:

- **CamCore Support:** https://camcore.au/support
- **Email:** `help@camcore.au`

For defects in upstream HaGeZi content, follow the upstream project's reporting process after confirming the issue does not originate from CamCore local policy.

## Licence

This repository is distributed under the [GNU General Public License v3.0](LICENSE).

Third-party source material remains subject to its applicable upstream licence and attribution requirements. See [`NOTICE.md`](NOTICE.md) for details.
