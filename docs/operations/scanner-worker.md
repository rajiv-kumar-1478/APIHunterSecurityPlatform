# Hosted Scanner Worker Operations Guide

## Current mode

The worker hosts durable scan consumption and campaign outcome processing, but the checked-in deployment disables scan consumption and uses `UnavailableScannerRuntime`. No scanner process starts in that mode.

## Tenant-owned execution flow

1. **Select and claim**: Query only queued jobs whose required `TenantId` equals the configured worker tenant, then claim atomically with worker ID/version fencing.
2. **Revalidate ownership and scope**: Reload the claim for the same tenant and reauthorize the registered target immediately before secrets or execution.
3. **Preserve actor semantics**: `RequestedByUserId` may be null for scheduler/system jobs. Never create a fake user or platform-admin context.
4. **Heartbeat**: Update liveness and `JobVersion`; cancel execution when claim ownership is lost.
5. **Acquire minimal secrets**: Lease only secrets required by the selected operational tool/provider and keep them in transient memory.
6. **Execute through sandbox**: Invoke `IScannerRuntimeSandbox`. Disabled mode returns `SCANNER_RUNTIME_DISABLED`; no host fallback is allowed.
7. **Persist canonical state**: Save sanitized receipt/status/findings and apply campaign counters with `CampaignOutcomeProcessedAtUtc` retry protection.
8. **Cleanup**: Dispose leases, stop heartbeat, terminate child process/container trees on cancellation, and delete guarded scratch directories.

## Operational readiness

A worker is ready to consume scans only when tenant configuration, PostgreSQL, target authorization, runtime executor, image provenance, egress boundary, secret source, and health probes are all valid. API health and scan admission must remain truthful when any required boundary is unavailable.

## Recovery

Stuck-job recovery uses heartbeat age and optimistic `JobVersion` fencing. Apply `20260905205518_AddScanJobTenantOwnership` only after all pre-tenant scan-job API, scheduler, and worker instances have drained; later token bridges support only tenant-schema-compatible clients. The authoritative real-PostgreSQL `CampaignSchedulerRaceTests` pass **9/9**, covering deterministic contention, complete-state claim reconciliation, unique occurrence enforcement, loser rollback, direct transient failures before and after commit, heartbeat recovery, missed-run advancement, full migration execution, stale `xmin`, rotating legacy `bytea` tokens, bidirectional `Version`/`JobVersion` fencing, non-vacuous timestamp precision, and unrelated database-failure isolation.

For an external server, set `TEST_POSTGRES_ALLOW_DATABASE_DROP=true` and target only a run-specific database matching `^apihunter_race_[0-9a-f]{32}$`; the fixture applies migrations, drops/recreates the approved target, and deletes it after each test. Without an explicit connection it uses an isolated Testcontainer. Never point this fixture at a shared or application database.
