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
3. **One local allow-list** — every name CamCore must never block: CamCore namespaces, the service hosts CamCore relies on, and evidenced exceptions.
4. **One local deny-list** — exact CamCore additions that must be included in the published feed.
5. **One validation and publishing pipeline** — failed or implausible generation never replaces the last-known-good production list.
6. **One controlled deployment model** — Pi-hole changes are made on Mars only and replicated to Venus by nebula-sync.

A larger number of blocklists is not considered an improvement by itself. CamCore favours predictable behaviour, low false-positive risk, traceable changes and simple rollback.

## How the feed is built

```text
HaGeZi Multi NORMAL
        │
        ▼
Validate upstream data
        │
        ▼
Add camcore/denylist.txt
        │
        ▼
Remove everything covered by camcore/allowlist.txt
        │
        ▼
Normalise • deduplicate • sort
        │
        ▼
Validate final output and size guard
        │
        ▼
blocklist.txt
        │
        ▼
CamCore Pi-hole resolvers
```

The publisher rejects malformed upstream data, refuses a build below 100,000 domains or more than 20% smaller than the current feed, removes every allow-listed name, and updates `blocklist.txt` only after a successful build. The allow-list is applied last, so it always wins over both upstream data and the local deny-list.

If generation fails, the existing production feed remains untouched.

## Protecting the services CamCore depends on

[`camcore/allowlist.txt`](camcore/allowlist.txt) lists the names CamCore must never block, grouped by service: CamCore and local namespaces, Microsoft 365 and Entra ID, Intune and Defender, GitHub, NetBird, Cameron-Media, operations platforms, host patching, CamCore Billing and the network edge.

| Entry | Matches |
| --- | --- |
| `host.example.com` | That exact name only |
| `*.example.com` | `example.com` and every name beneath it |

Namespace (`*.`) entries are used only where no name beneath the domain is a tracker or telemetry host. Where a vendor serves telemetry from the same parent domain, such as `analytics.plex.tv` or `collector.github.com`, only the exact service hosts are listed, so that telemetry stays blocked.

Three controls enforce the list:

1. **Publisher** — removes every covered name from the upstream data before publication and lists each hit in the workflow run summary, so an upstream change that would have blocked a CamCore service is visible.
2. **Validator** — rejects malformed entries, a deny-list entry that conflicts with the allow-list, and removal of the required CamCore namespaces.
3. **Source health** — downloads the whole published feed after every publication and daily, and fails if it contains any allow-listed name.

When CamCore adopts a new service, add its hosts to the allow-list in the same change that adds it to the Active Service Register.

## Current production standard

| Component | State | Production role |
| --- | --- | --- |
| **CamCore DNS Blocklist** | Active | Single approved Pi-hole production feed |
| **HaGeZi Multi NORMAL** | Active upstream | Approved source material for the CamCore feed |
| **CamCore allow-list** | Active | Guarantees CamCore services and approved exceptions are never published |
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

It validates repository policy, downloads the published CamCore production feed, and confirms it is reachable, holds at least 100,000 entries and blocks no allow-listed name.

## Resolver deployment standard

CamCore runs two Pi-hole resolvers: **Mars** (primary) and **Venus** (secondary). nebula-sync on Mars replicates the Mars Pi-hole configuration to Venus every 15 minutes and runs gravity on Venus after each sync. Venus is a configuration mirror, not an independent test stage.

1. Make Pi-hole configuration changes on **Mars only**. A change made on Venus is overwritten at the next sync.
2. For a higher-risk change, pause nebula-sync first so a fault on Mars cannot reach Venus.
3. Rebuild gravity on Mars and query Mars directly.
4. Validate general internet access, the intended block or allow behaviour, Microsoft 365 and identity, NetBird, CamCore public and private services, and commonly used household applications.
5. Resume nebula-sync. After the next sync, query Venus directly and confirm both resolvers report the same gravity count.
6. Record any significant production change in CamCore Operations.

**A merged policy change is a production change.** The publisher runs when policy files change on `main`. Venus re-reads the feed at the next nebula-sync gravity run, within about 15 minutes, and Mars at its next scheduled gravity update. Merge only when you are ready to validate.

The full procedure and rollback requirements are in [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Change control

Every production DNS change must be deliberate and reversible.

A change should:

- state the reason and supporting evidence;
- identify the exact source or domain entry affected;
- assess likely impact and false-positive risk;
- pass repository validation and tests;
- publish successfully before resolver rollout;
- be validated on Mars before replication to Venus is confirmed;
- include a defined rollback path; and
- be recorded in CamCore Operations when operationally significant.

For local exceptions, prefer the smallest exact domain required. A new `*.` namespace entry is an exceptional change: confirm that it covers no tracker or telemetry host, and review the publisher run summary after merge.

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
