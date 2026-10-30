# CamCore DNS Repository Standard

This document defines the required GitHub repository controls for `Team-CamCore/dns-blocklists`.

Version-controlled policy and automation are only one part of the control model. Repository settings should prevent unvalidated changes from bypassing the CamCore DNS publishing process.

## Repository identity

- **Default branch:** `main`
- **Provenance branch:** `upstream-hagezi`
- **Visibility:** Public
- **Merge strategy:** Squash merge only
- **Recommended description:** `CamCore-managed DNS filtering policy, publishing and source governance.`
- **Recommended topics:** `camcore`, `dns`, `pihole`, `blocklist`, `security`

The repository should remain clearly identified as a CamCore-managed production policy repository while preserving its upstream fork relationship and attribution.

## Required protection for `main`

`main` should be protected so ordinary production changes cannot bypass review and validation.

Required controls:

- Require changes through a pull request.
- Require the `Validate policy, local lists and tests` status check before merge.
- Require conversation resolution before merge.
- Block force pushes.
- Block branch deletion.
- Keep administrator bypass available only for documented emergency recovery.
- Do not require an external approval when CamCore has only one repository maintainer; use the mandatory validation check and documented CamCore change-control process instead.

The publishing workflow must still be able to update the generated `blocklist.txt` on `main`. Branch-protection changes must therefore be tested against the automated publication path before being considered complete.

## Branch separation

The `upstream-hagezi` branch is a provenance and controlled-reference branch only.

Do not:

- configure it as the default branch;
- deploy it to Pi-hole;
- merge it into `main`;
- include it in ordinary feature-branch cleanup; or
- use automatic fork synchronisation to bring upstream repository content into `main`.

## GitHub Actions

Repository Actions settings should follow least privilege:

- Default workflow permissions should be read-only.
- GitHub Actions should not be allowed to create or approve pull requests.
- Workflows from untrusted outside contributors should require approval before execution.
- Only CamCore-approved workflows should exist on `main`.
- Third-party Actions should be pinned to immutable commit SHAs.

The intended workflow permission model is:

| Workflow | Permission model | Purpose |
| --- | --- | --- |
| `camcore-validate.yml` | Read-only | Validate policy and run tests |
| `camcore-source-health.yml` | Read-only | Check the published production feed |
| `camcore-publish.yml` | Repository contents write | Replace `blocklist.txt` after successful generation |

`camcore-publish.yml` is the only intentionally write-capable workflow on the default branch.

## Security controls

Enable, where available:

- Dependabot alerts;
- Dependabot security updates;
- secret scanning;
- push protection; and
- appropriate code-scanning or dependency review controls.

Security and dependency findings should be reviewed through CamCore Operations.

Never publish resolver exports, DNS query logs, credentials, private keys, client information, private infrastructure inventories or browsing data in this public repository.

## Merge policy

- Use squash merging for policy, documentation and tooling changes.
- Use clear conventional commit subjects such as `fix(dns): allow required authentication domain`.
- Delete ordinary feature branches after merge.
- Never delete `upstream-hagezi` as part of automatic branch cleanup.
- Do not merge a production-facing change until required validation has passed.

## Operational verification

Repository settings should be reviewed after material GitHub configuration changes and during periodic CamCore maintenance.

Verify that:

1. `main` remains the default branch;
2. required branch protection is active;
3. the CamCore validation status check is enforced;
4. squash merging remains the approved merge method;
5. the publisher can still refresh `blocklist.txt` successfully;
6. no unexpected write-capable workflows exist; and
7. `upstream-hagezi` remains isolated from production.
