# CamCore DNS Filtering Operations

## Objective

Apply DNS filtering changes safely, consistently and with a tested rollback path across the CamCore primary and secondary Pi-hole resolvers.

CamCore uses a minimal-list policy. The approved production source is defined in `camcore/sources.json`. A source or local entry is not approved merely because it exists elsewhere in this fork.

## Change categories

| Category | Example | Required handling |
| --- | --- | --- |
| Source maintenance | Approved source URL or metadata correction | Validate, stage and verify |
| Allow-list exception | A legitimate service is blocked | Investigate first; allow the smallest exact domain |
| Local deny-list entry | A specific confirmed threat or unwanted domain | Document evidence and impact |
| New source evaluation | Testing an additional upstream list | Keep out of production until separately approved |
| Emergency rollback | A change disrupts essential access | Revert immediately, verify and record |

## Before the change

1. Create or update the matching CamCore Operations record when the change is significant.
2. State the reason, evidence, affected services and expected result.
3. Confirm the current production source selection matches `camcore/sources.json`.
4. Back up the resolver configuration using the approved Pi-hole backup method.
5. Record the last known working list configuration.
6. Confirm both resolvers are healthy before making any change.
7. Prepare exact test queries and service checks.
8. Define the rollback action before deployment.

Do not use live resolver exports or query logs as repository attachments. Store operational evidence only in an approved private system.

## Staged deployment

Apply the change to one resolver first, normally the secondary resolver.

### Replication and feed isolation

Before staging, inspect the deployed configuration replication and gravity schedules. Automatic full configuration sync can overwrite a secondary-only test or propagate a faulty primary change to both resolvers. A shared mutable feed can also reach both resolvers through their independent scheduled gravity updates.

1. Record replication settings and the last successful sync in the private Operations record.
2. Pause configuration replication using its supported administration interface, and verify it is paused.
3. Control scheduled gravity refreshes during the test window, or use separate immutable candidate and last-known-good feed URLs.
4. Back up both resolver configurations privately and record the exact last-known-good feed revision.
5. Stage the candidate on the secondary resolver using a commit-pinned feed URL; retain the working configuration and feed on the primary.
6. Do not publish a policy change to the shared production feed until secondary validation passes.
7. After approval and validation, deploy the same candidate to the primary. Restore the canonical feed URL on both resolvers only after confirming it contains the validated output.
8. Restore the recorded schedules and replication settings, verify a successful sync, and repeat direct queries against both resolvers.

If replication or feed isolation cannot be verified, stop the rollout. Do not claim staged deployment while automatic propagation remains active.

### Resolver health checks

Check more than the blocking-enabled flag: require a non-empty gravity database, successful recent gravity updates, the approved enabled adlist and group assignments, a known blocked-domain query, and successful public and private queries. Alert on an empty database, failed or overdue refresh, unexpected source changes, and resolver mismatch. Establish expected counts from the current validated feed; historical fixed counts are not reliable drift thresholds.

The repository source-health workflow checks feed availability and plausible content only. It does not prove resolver health, successful application sign-in, or feed freshness. Record those separately in private monitoring.

1. Add or remove only the approved source or exact local entry.
2. Rebuild gravity using the resolver's supported Pi-hole command or interface.
3. Confirm the DNS service remains active.
4. Query the test resolver directly so the result cannot come from the other resolver.
5. Test the intended block or allow behaviour.
6. Test representative unaffected domains.
7. Review Pi-hole logs for unexpected failures without copying private logs into this repository.
8. Leave the other resolver unchanged until the first-stage checks pass.

After successful validation, repeat the same controlled change on the primary resolver.

## Verification checklist

Confirm on both resolvers:

- DNS resolution is healthy.
- General internet access works.
- Microsoft 365 sign-in and core services work.
- CamCore public services resolve and load.
- CamCore private services resolve through the approved network path.
- NetBird-connected clients retain expected DNS behaviour.
- The intended domain is blocked or allowed.
- No unexpected spike in blocked requests or resolver errors is visible.
- The configured source set still matches the approved manifest.

Where command-line access is available, use direct resolver queries and the supported Pi-hole status and gravity commands. Do not copy example commands with placeholder addresses into production without confirming the target.

## Allow-list procedure

1. Reproduce the user or service problem.
2. Confirm Pi-hole blocked the relevant query.
3. Identify the smallest exact domain needed.
4. Check whether the domain is a dependency, tracker, content host or authentication endpoint.
5. Test a temporary exception on one resolver.
6. Verify that the affected service works and unrelated blocking remains intact.
7. Add the exact domain to `camcore/allowlist.txt` in sorted order.
8. Run repository validation and record the reason.

Avoid broad parent-domain exceptions unless every subdomain is deliberately required and the risk has been reviewed.

## Deny-list procedure

1. Confirm the domain and evidence.
2. Check for legitimate or shared-hosting use.
3. Determine whether the entry belongs in an upstream project.
4. Test the exact domain on one resolver.
5. Verify the intended result and likely user impact.
6. Add the exact domain to `camcore/denylist.txt` in sorted order.
7. Run repository validation and record the reason.

## New source evaluation

An additional list must remain outside production while under review.

Evaluation should measure:

- Added unique domains rather than total headline size.
- False positives affecting household, media and business services.
- Microsoft 365 and identity impact.
- Mobile application behaviour.
- NetBird and private-service access.
- Resolver load, gravity update duration and database growth.
- Maintenance quality, licence, provenance and update reliability.
- Whether the source addresses a requirement not already met by the approved baseline.

A successful technical test does not by itself approve production deployment.

## Rollback

When a DNS change causes disruption:

1. Stop further rollout and pause automatic replication and gravity updates to prevent the faulty state from spreading.
2. Restore the previous source selection or remove the new local entry.
3. Rebuild gravity.
4. Confirm the DNS service is healthy.
5. Query both resolvers directly.
6. Re-test internet, Microsoft 365, NetBird and CamCore services.
7. Restore the saved configuration if a simple reversal is insufficient.
8. Record the impact, rollback and follow-up action in CamCore Operations.

Do not compensate for an unclear failure by adding multiple broad allow-list entries.

## Post-change record

Record:

- What changed.
- Why it changed.
- Which resolver was tested first.
- Validation results.
- Whether rollback was required.
- Any upstream report created.
- The final production source and exception state.
