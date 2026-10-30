# CamCore DNS Upstream Governance

## Purpose

This document defines how **CamCore – Cameron Family Secure Network** consumes, attributes and governs third-party DNS filtering sources.

The production source of truth is [`camcore/sources.json`](../camcore/sources.json). Upstream content is never considered production-approved merely because it exists in this fork, appears on the provenance branch or is technically compatible with Pi-hole.

## Repository origin

`Team-CamCore/dns-blocklists` (formerly `camcoreau/dns-blocklists`) originated as a GitHub fork of [`hagezi/dns-blocklists`](https://github.com/hagezi/dns-blocklists).

HaGeZi and its contributors retain authorship of their upstream generated lists, source documentation and other original material. CamCore retains the applicable upstream licence and does not claim authorship of HaGeZi content. The inherited HaGeZi material remains subject to **GPL-3.0** and its applicable upstream attribution requirements.

## Current production relationship

**HaGeZi Multi NORMAL is the approved upstream source material for the CamCore production DNS blocklist.**

The production relationship is intentionally controlled:

1. `camcore/sources.json` identifies the active production policy and approved upstream URL.
2. The CamCore publisher downloads the approved HaGeZi Multi NORMAL domains feed over HTTPS.
3. Upstream data is validated before processing.
4. Domains in `camcore/denylist.txt` are added.
5. Every name covered by `camcore/allowlist.txt` is removed.
6. The result is normalised, deduplicated, sorted and validated.
7. A successful build is published as the CamCore-owned `blocklist.txt` URL used by CamCore resolvers.
8. A failed build leaves the last-known-good production feed untouched.

CamCore resolvers therefore consume the **CamCore production URL**, not the upstream HaGeZi URL directly.

Using HaGeZi as production source material does not mean:

- CamCore claims authorship of HaGeZi entries;
- CamCore independently verifies every upstream domain individually;
- every HaGeZi list or category is approved for CamCore;
- the full upstream repository is mirrored into CamCore production; or
- upstream changes may bypass CamCore validation, resolver validation or change control.

## Branch separation

The default `main` branch contains the CamCore-owned governance, policy, tooling and published production feed.

The `upstream-hagezi` branch preserves the inherited upstream fork snapshot for provenance and controlled reference. It is **not**:

- a production deployment branch;
- a list mirror intended for Pi-hole subscription;
- an alternative source of truth for CamCore policy; or
- a branch that should be merged into `main`.

The `upstream-hagezi` branch **must not be merged into `main`**.

CamCore policy references approved upstream content through `camcore/sources.json` instead of copying the upstream-generated repository tree into the default branch.

## Reviewing upstream changes

Upstream changes should be consumed through the approved source pipeline rather than blindly synchronised into `main`.

When reviewing an upstream change or refreshing provenance material:

1. Review the relevant upstream commit range, source change or release notes.
2. Confirm licence and attribution requirements remain satisfied.
3. Keep inherited upstream repository automation out of `main`.
4. Update `upstream-hagezi` only when a provenance refresh is intentionally required.
5. Change `camcore/sources.json` only through a deliberate CamCore production-policy change.
6. Run the CamCore validator and unit tests after policy or governance changes.
7. Validate production-impacting changes on Mars before confirming replication to Venus.
8. Record significant production decisions in CamCore Operations.

An upstream source update becoming available does not by itself authorise a CamCore policy change.

## Additional source evaluation

Any additional third-party blocklist must remain outside production until separately reviewed and approved.

Evaluation should consider:

- unique coverage added beyond the current baseline;
- false-positive risk;
- Microsoft 365 and identity impact;
- NetBird and private-service behaviour;
- common household and media applications;
- source maintenance quality and provenance;
- licence compatibility;
- update reliability; and
- operational cost relative to the problem being solved.

CamCore intentionally prefers a minimal, explainable filtering baseline over accumulating multiple overlapping lists.

## Retired source

[StevenBlack Unified Hosts](https://github.com/StevenBlack/hosts) is retained in `camcore/sources.json` as the previous CamCore production baseline.

It is **retired** and must not be treated as an active production source unless a future reviewed change explicitly changes the manifest state.

## Inherited automation

The upstream fork contains automation intended for the upstream maintainer, including workflows for release management, issue handling and repository maintenance.

Those workflows are intentionally absent from the CamCore `main` branch. CamCore keeps only the narrow automation required to validate policy, publish the approved production feed and check source health.

## Reporting upstream problems

Confirm the issue and collect only non-sensitive evidence before reporting an upstream defect.

Use the upstream project's published reporting process for:

- incorrect or missing upstream entries;
- source-quality concerns;
- generated-list or format defects; and
- upstream documentation errors.

Keep CamCore-specific policy, resolver deployment details, local exceptions and private operational evidence within CamCore-owned systems.

See [`NOTICE.md`](../NOTICE.md) for attribution and licence notes.
