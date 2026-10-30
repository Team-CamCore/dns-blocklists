## Summary

Describe the exact CamCore DNS policy, local-list, documentation, tooling or automation change.

## Reason and evidence

Explain the specific operational, security or governance requirement being addressed.

Do not include DNS query logs, browsing information, client details, credentials, private infrastructure inventories or other sensitive operational data.

## Scope

Identify the exact source, file or domain entry affected and confirm that the change is no broader than required.

## Risk and impact

Describe expected impact and false-positive risk, including any relevant effect on:

- general internet access;
- Microsoft 365 and identity;
- NetBird and private-service access;
- CamCore public and private services; and
- commonly used household or media applications.

## Validation

- [ ] The change follows CamCore's minimal-list policy.
- [ ] Any local exception uses the smallest exact domain required.
- [ ] Any new `*.` allow-list namespace covers no tracker or telemetry host in the current `blocklist.txt`.
- [ ] Any new upstream source is explicitly being evaluated or has been separately approved for production.
- [ ] `python -m unittest discover -s camcore/tests -v` passes.
- [ ] `python camcore/tools/validate_repository.py` passes.
- [ ] Upstream attribution and licence information remain correct.
- [ ] Production-impacting behaviour has a Mars validation and Venus replication plan.
- [ ] A rollback method is documented below.
- [ ] The change is recorded in CamCore Operations when operationally significant.

## Deployment

Merging a policy change publishes it to production. For production-impacting changes, state whether nebula-sync will be paused, the checks to run against Mars, and how replication to Venus will be confirmed.

Use `Not applicable` for documentation-only changes.

## Rollback

State exactly how the previous known-working DNS state will be restored if validation fails or the change causes disruption.
