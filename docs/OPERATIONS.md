# CamCore DNS Filtering Operations

## Objective

Apply DNS filtering changes safely, consistently and with a tested rollback path across the CamCore Pi-hole resolvers: **Mars** (primary) and **Venus** (secondary).

CamCore uses a minimal-list policy. The approved production source is defined in `camcore/sources.json`. A source or local entry is not approved merely because it exists elsewhere in this fork.

## Change categories

| Category | Example | Required handling |
| --- | --- | --- |
| Source maintenance | Approved source URL or metadata correction | Validate, stage and verify |
| Allow-list exception | A legitimate service is blocked | Investigate first; allow the smallest exact domain |
| Service protection | CamCore adopts a new platform | Add its service hosts to the allow-list with the service-register change |
| Local deny-list entry | A specific confirmed threat or unwanted domain | Document evidence and impact |
| New source evaluation | Testing an additional upstream list | Keep out of production until separately approved |
| Emergency rollback | A change disrupts essential access | Revert immediately, verify and record |

## Before the change

1. Create or update the matching CamCore Operations record when the change is significant.
2. State the reason, evidence, affected services and expected result.
3. Confirm the current production source selection matches `camcore/sources.json`.
4. Back up the resolver configuration using the approved Pi-hole backup method.
5. Record the last known working list configuration.
6. Confirm both resolvers are healthy and report the same gravity count before making any change.
7. Prepare exact test queries and service checks.
8. Define the rollback action before deployment.

Do not use live resolver exports or query logs as repository attachments. Store operational evidence only in an approved private system.

## Deployment model

### How a change reaches the resolvers

- **Pi-hole configuration** (adlists, local records, groups, local allow or deny entries) is changed on **Mars only**. nebula-sync on Mars performs a full sync to Venus every 15 minutes and runs gravity on Venus after each sync. A change made only on Venus is overwritten at the next sync; a fault on Mars reaches Venus within 15 minutes.
- **Feed content** (anything that changes `blocklist.txt`) goes live when the publisher runs on `main`. Mars and Venus rebuild gravity on the same 15-minute cycle. On 30 October 2026 both rebuilt in the same second at 21:00, 21:15, 21:45 and 22:00 AEDT, and both loaded the feed published at 21:47 at 22:00. A published feed change therefore reaches **both** resolvers within about 15 minutes.

What triggers the 15-minute rebuild on Mars is not yet confirmed; it may be a cron entry or a nebula-sync setting. Until it is, do not rely on pausing nebula-sync to keep a feed change off either resolver. To identify the trigger, run on Mars:

```bash
sudo crontab -l; cat /etc/cron.d/pihole
```

```bash
docker inspect nebula-sync --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -v -i -E 'password|token|secret|key'
```

Venus is a configuration mirror of Mars. It protects against host failure on Mars, not against configuration error. Do not describe Venus as an independent test stage.

### Pi-hole configuration change

1. For a higher-risk change, pause nebula-sync on Mars and confirm it is paused.
2. Apply the change on Mars and rebuild gravity with `pihole -g`.
3. Confirm `pihole-FTL` remains active.
4. Query Mars directly so the result cannot come from Venus.
5. Test the intended block or allow behaviour and representative unaffected domains.
6. Run the verification checklist below against Mars.
7. Resume nebula-sync. After the next sync, query Venus directly and repeat the key checks.
8. Confirm both resolvers report the same gravity count.

### Feed policy change (this repository)

1. Open a pull request. Confirm the validation workflow ran and passed; an absent status is not a pass.
2. Merge only when you are ready to validate, because the publisher runs on merge.
3. Confirm the publish workflow succeeded and review its run summary for allow-list hits and the published entry count.
4. Within about 15 minutes, both resolvers load the new feed. To validate sooner, run `pihole -g` on Mars.
5. Query Mars directly and run the verification checklist, then query Venus directly and repeat the key checks.
6. Confirm both resolvers report the same gravity count as the `# Entries:` header of the published feed.
7. Confirm the source-health workflow passed after publication.

For a high-risk feed change, do not publish it to `blocklist.txt` first. Instead:

1. Publish the candidate to a separate feed file in this repository.
2. Pause nebula-sync on Mars and confirm it is paused.
3. Point only the Mars adlist at the candidate URL and run `pihole -g`.
4. Validate Mars. Venus keeps its current adlist and gravity throughout.
5. Resume nebula-sync once Mars has passed, and confirm Venus matches after the next sync.

Rollback is to point the Mars adlist back at `blocklist.txt`. OPS-1062 uses this method.

If replication state cannot be confirmed, stop the rollout.

### Resolver health checks

Check more than the blocking-enabled flag: require a non-empty gravity database, successful recent gravity updates, exactly one enabled adlist (the CamCore feed), a known blocked-domain query, and successful public and private queries. Alert on an empty or collapsed gravity count, a count that differs between Mars and Venus, an overdue refresh and any unexpected adlist. The published feed header states the expected entry count.

The repository source-health workflow proves the published feed is reachable, plausibly sized and free of allow-listed names. It does not prove resolver health or successful application sign-in. Record those in private monitoring.

Do not use live resolver exports or query logs as repository evidence.

## Verification checklist

Confirm on Mars, then on Venus after replication:

- DNS resolution is healthy.
- General internet access works.
- Microsoft 365 sign-in and core services work.
- CamCore public services resolve and load.
- CamCore private services resolve through the approved network path.
- NetBird-connected clients retain expected DNS behaviour.
- The intended domain is blocked or allowed.
- No unexpected spike in blocked requests or resolver errors is visible.
- The configured source set still matches the approved manifest.
- Mars and Venus report the same gravity count.

Where command-line access is available, use direct resolver queries and the supported Pi-hole status and gravity commands. Do not copy example commands with placeholder addresses into production without confirming the target.

## Allow-list procedure

### Fixing a blocked service

1. Reproduce the user or service problem.
2. Confirm Pi-hole blocked the relevant query (`pihole -q <domain>` on Mars).
3. Identify the smallest exact domain needed.
4. Check whether the domain is a dependency, tracker, content host or authentication endpoint.
5. For an urgent fix, add a temporary exact allow entry on Mars with `pihole allow <domain>`; never disable the adlist, because that removes filtering from both resolvers once nebula-sync runs.
6. Verify that the affected service works and unrelated blocking remains intact.
7. Add the exact domain to the matching service section of `camcore/allowlist.txt`, in sorted order.
8. Run repository validation, merge, confirm publication, then remove the temporary Pi-hole entry on Mars.

### Protecting a service CamCore depends on

When CamCore adopts a platform, add its service hosts to `camcore/allowlist.txt` in the same change that adds it to the Active Service Register. Use `*.domain` only when nothing beneath the domain is a tracker or telemetry host; check the current `blocklist.txt` first, because a namespace entry unblocks every listed name beneath it. List exact hosts where a vendor also serves telemetry from the same parent domain.

Avoid broad parent-domain exceptions unless every subdomain is deliberately required and the risk has been reviewed.

## Deny-list procedure

1. Confirm the domain and evidence.
2. Check for legitimate or shared-hosting use.
3. Determine whether the entry belongs in an upstream project.
4. Test the exact domain on Mars with `pihole deny <domain>`.
5. Verify the intended result and likely user impact.
6. Add the exact domain to `camcore/denylist.txt` in sorted order. The validator rejects an entry covered by the allow-list.
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

1. Stop further rollout. For a configuration fault that has not reached Venus, pause nebula-sync on Mars. A feed fault reaches both resolvers on the 15-minute gravity cycle, so revert it promptly.
2. For a feed fault, revert the merge on `main` and run the publish workflow manually; for a configuration fault, restore the previous setting on Mars.
3. Rebuild gravity on Mars with `pihole -g`.
4. Confirm the DNS service is healthy.
5. Query Mars and Venus directly, and resume nebula-sync once Mars is correct.
6. Re-test internet, Microsoft 365, NetBird and CamCore services.
7. Restore the saved configuration if a simple reversal is insufficient.
8. Record the impact, rollback and follow-up action in CamCore Operations.

Do not compensate for an unclear failure by adding multiple broad allow-list entries.

## Post-change record

Record:

- What changed.
- Why it changed.
- Mars validation results and confirmation of replication to Venus.
- Whether rollback was required.
- Any upstream report created.
- The final production source and exception state.
