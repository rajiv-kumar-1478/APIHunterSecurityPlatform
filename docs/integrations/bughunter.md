# BugHunter Provider Boundary

## Availability

BugHunter is a planned hosted-provider compatibility boundary, not an available scanner integration. `BugHunterScanProvider` returns `BUGHUNTER_CONTRACT_UNAVAILABLE` and a blocked/unavailable status for every operation.

Do not assign or advertise a version, image, capability set, credential requirement, external scan ID, progress model, result schema, artifact location, cancellation behavior, or health state until it is verified from an authoritative upstream contract.

## Required contract before enablement

An operational BugHunter integration requires all of the following:

1. Authoritative upstream repository/ownership and immutable release or commit.
2. Digest-pinned OCI image or another explicitly approved execution artifact.
3. Exact CLI or API commands, arguments, authentication, timeout, and exit-code semantics.
4. Stable start/status/result/cancel behavior, including idempotency and retry rules.
5. Versioned output schema and bounded parser fixtures from authentic output.
6. Artifact retention, sanitization, provenance, and deletion semantics.
7. Non-root sandbox, resource limits, process-tree cancellation, and enforced egress.
8. Target-scope and tenant-isolation tests.
9. Unavailable-by-default tests proving no host or generic fallback.
10. Live comparison and failure-path validation in a Docker-capable environment.

## Current compatibility behavior

```text
Platform request
    └─ BugHunterScanProvider
         └─ BUGHUNTER_CONTRACT_UNAVAILABLE (Blocked)
```

No secret lease or scanner process should be started by this path. This stable unavailable contract keeps API/UI behavior truthful while allowing a future implementation behind the same provider boundary.

## Replacement or activation procedure

Only after the contract above is approved:
- implement the provider/adapter and canonical result mapping;
- register immutable capabilities and health probes;
- add parser, provider-contract, sandbox, egress, cancellation, and provenance tests;
- run live comparison scans against authorized test targets;
- enable the provider explicitly, with fail-closed rollback to unavailable behavior.
