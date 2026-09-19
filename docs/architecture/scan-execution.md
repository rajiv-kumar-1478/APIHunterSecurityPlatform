# Hosted Scan Execution Architecture Specification

## Current availability

The scan-job lifecycle and persistence contract are implemented, but the checked-in production/Compose runtime is deliberately disabled. `UnavailableScannerRuntime` returns `SCANNER_RUNTIME_DISABLED`; no host-process fallback is permitted. BugHunter is also unavailable pending an authoritative provider contract.

## Tenant-owned job lifecycle

```text
Security API / Campaign Scheduler
            │
            ├─ require configured TenantId
            ├─ validate registered target and scope
            └─ persist SecurityScanJob
                 TenantId: required ownership
                 RequestedByUserId: optional actor provenance
                 Status: Queued
            │
            ▼
Tenant-scoped worker consumer
            │
            ├─ atomically claim eligible queued job
            ├─ revalidate tenant target/scope
            ├─ heartbeat and fence ownership with JobVersion
            ├─ execute only through IScannerRuntimeSandbox
            └─ persist receipt, terminal status, and campaign outcome marker
            │
            ▼
Canonical parsing, sanitized evidence, findings, reports, and audit data
```

The worker context is anonymous and explicitly non-admin. Scheduler/system jobs do not fabricate a user ID. A disabled runtime terminalizes execution with a stable fail-closed result before any scanner process starts.

## Execution boundaries

1. **Ownership**: API and worker use the same required configured tenant. Durable job ownership never comes from request headers, cookies, user IDs, or `Guid.Empty`.
2. **Authorization**: Target and repository scope are rechecked immediately before secret access or execution.
3. **Secrets**: Acquire only the lease required by the selected tool/provider, keep it in memory, and dispose it in all paths.
4. **Runtime**: Invoke `IScannerRuntimeSandbox`; never bypass it with an implicit local process.
5. **Heartbeat/cancellation**: Active workers renew lease state and terminate process trees on cancellation or lease loss.
6. **Persistence**: Store canonical receipts and sanitized evidence. Apply campaign terminal outcomes and `CampaignOutcomeProcessedAtUtc` atomically/retry-safely.

## Canonical profiles

- **Recon**: discovery capabilities such as subdomain enumeration, DNS resolution, and HTTP probing.
- **Standard**: web assessment capabilities such as HTTP probing, crawling, and vulnerability scanning.
- **Deep**: broader discovery and assessment capabilities, including optional AI/report capabilities only when authoritative tools are available.

Profile capability definitions do not make any named tool available. Planning must fail closed when no compatible, healthy, operational tool/runtime exists.
