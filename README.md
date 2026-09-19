# APIHunter Security Intelligence Platform

> .NET 10 + EF Core 10 + Next.js 16.3.0 + PostgreSQL security intelligence platform with tenant-owned campaign scheduling, canonical findings, remediation, and fail-closed scanner orchestration.

[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16.3.0-black.svg)](https://nextjs.org/)
[![Unit inventory](https://img.shields.io/badge/unit%20tests-795%20passing-brightgreen.svg)]()
[![Integration inventory](https://img.shields.io/badge/integration%20tests-106%20passing-brightgreen.svg)]()

## Current production posture

### Authentication, authorization, and CSRF
- Browser authentication is cookie-only through `__ap_session`; `sub` is the stable user ID and `sid` is the persisted `AuthenticationSession.Id`.
- Every authenticated request revalidates session revocation/expiry, enabled-user state, identity match, and current platform-admin state from PostgreSQL.
- Cookies use fixed, non-sliding expiry. Active sessions are capped; user disablement and admin demotion revoke active sessions.
- Authorization defaults to authenticated access with an explicit `PlatformAdmin` policy. Login has an IP fixed-window rate limit.
- Anonymous `GET /api/v1/auth/csrf` bootstraps antiforgery state. Every unsafe MVC request requires `X-CSRF-TOKEN`; rejection returns `INVALID_CSRF_TOKEN`.
- The dashboard uses one shared API client with `credentials: "include"` and module-memory CSRF. It stores no bearer token or auth state in local/session storage.

### Tenant ownership
- API and worker require a configured, non-empty tenant at startup.
- `SecurityScanJob.TenantId` is required durable ownership; `RequestedByUserId` is nullable actor provenance for scheduler/system jobs.
- Worker identity is anonymous/non-admin, and scan consumption/campaign reconciliation are tenant-scoped.

### Scanner availability

> **Scanner execution is unavailable by default and in the checked-in Compose deployment.** `UnavailableScannerRuntime` fails closed with `SCANNER_RUNTIME_DISABLED`. BugHunter is a compatibility boundary that returns `BUGHUNTER_CONTRACT_UNAVAILABLE` until authoritative image/API/CLI, authentication, output, cancellation, artifact, egress, and isolation contracts exist.

No manifest, parser fixture, mock, or health record is proof that a scanner is operational. Enabling execution requires digest-pinned artifacts, a physical sandbox boundary, enforced egress, and successful live Docker validation.

## Architecture

```text
Browser (Next.js)
  └─ cookie + CSRF
       └─ Platform.Api
            ├─ PostgreSQL: users, sessions, findings, campaigns, scan jobs
            ├─ canonical security/remediation/AI APIs
            └─ private Platform.Worker
                 ├─ configured tenant boundary
                 ├─ durable claim + heartbeat + campaign outcome handling
                 └─ IScannerRuntimeSandbox (currently disabled/fail-closed)
```

The capability/planning/parser/provenance contracts remain scanner-independent. A generic CLI tool can be configuration-driven only after it conforms to the approved executable, parser, manifest, sandbox, and egress contracts. A new typed adapter still requires code and tests.

## Deployment topology

The checked-in Compose topology contains PostgreSQL, API, worker, and frontend services:
- API, worker, and frontend images run as non-root users.
- The worker exposes no public port and joins private backend plus outbound networks.
- API and worker share persisted ASP.NET Core Data Protection keys and the same application name.
- PostgreSQL, API, and frontend have health checks.
- Scanner runtime, scan consumption, and campaign scheduling remain disabled until a real isolation boundary is configured and validated.

See [`docs/operations/render-railway-deployment.md`](./docs/operations/render-railway-deployment.md) for the scanner-enabled acceptance gate; it is a proposed architecture, not a claim of current deployment.

## Credential validation scope

Nineteen provider validators are implemented and registered in both API and worker.

- Bespoke validators: OpenAI, Anthropic, DeepSeek, Groq, AWS STS, GitHub, Stripe, SendGrid, Mailgun, Slack.
- Declarative validators: HuggingFace, Perplexity, Cohere, FireworksAI, Replicate, OpenRouter, xAI, Cerebras, Tavily.

The remaining 15 providers in the 34-provider matrix are still deferred and resolve through the zero-network unsupported fallback. Declarative providers share one tested request/response engine (`ProviderValidationExecutor`) and a server-controlled descriptor; every destination must be allowlisted in `ValidationEndpointRegistry`, and candidate-supplied URLs are always rejected. Credential validation capability is independent of scanner/BugHunter availability, and a `Valid` result is only ever produced by a real provider response.

## Selected API routes

This is a selected catalog, not the complete controller surface.

### Authentication
```http
GET    /api/v1/auth/csrf
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{id}
```

### Scan jobs and runtime
```http
GET    /api/v1/security/scans/capabilities
GET    /api/v1/security/scans/tools
GET    /api/v1/security/scans/runtime/health
GET    /api/v1/security/scans/providers
GET    /api/v1/security/scans/jobs
POST   /api/v1/security/scans/jobs
GET    /api/v1/security/scans/jobs/{id}
GET    /api/v1/security/scans/jobs/{id}/receipt
GET    /api/v1/security/scans/jobs/{id}/summary
GET    /api/v1/security/scans/jobs/{id}/diff
GET    /api/v1/security/scans/jobs/{id}/report[/{format}]
GET    /api/v1/security/scans/jobs/{id}/provenance
GET    /api/v1/security/scans/jobs/{id}/invocations
POST   /api/v1/security/scans/jobs/{id}/retry
POST   /api/v1/security/scans/jobs/{id}/cancel
```

### Campaigns and observability
```http
GET    /api/v1/security/campaigns
POST   /api/v1/security/campaigns
GET    /api/v1/security/campaigns/health
GET    /api/v1/security/campaigns/metrics
GET    /api/v1/security/campaigns/{id}
PUT    /api/v1/security/campaigns/{id}
DELETE /api/v1/security/campaigns/{id}
POST   /api/v1/security/campaigns/{id}/pause
POST   /api/v1/security/campaigns/{id}/resume
POST   /api/v1/security/campaigns/{id}/run-now
GET    /api/v1/security/campaigns/{id}/audit-logs
GET    /api/v1/security/campaigns/{id}/history
GET    /api/v1/security/campaigns/{id}/diagnostics
```

### Findings
```http
GET    /api/v1/findings
GET    /api/v1/findings/{id}
GET    /api/v1/findings/{id}/evidence
GET    /api/v1/findings/{id}/history
PATCH  /api/v1/findings/{id}/status
```

## Dashboard routes

The worktree contains 13 App Router pages: `/`, `/apihunter`, `/audit`, `/credentials`, `/dashboard`, `/health`, `/login`, `/permissions`, `/security`, `/security/remediation`, `/settings/ai`, `/settings/notifications`, and `/users`.

## Persistence and dependencies
- EF migration history and snapshot are reconciled through `20260906024820_FixPostgreSqlRowVersionTokens`.
- Tenant migration backfills campaign ownership first, then established legacy requester ownership, and aborts if unresolved/empty ownership remains.
- `20260905205518_AddScanJobTenantOwnership` is a deployment stop/drain boundary: every pre-tenant scan-job API, scheduler, and worker binary must stop before it is applied.
- After that boundary, repository and analysis-job concurrency uses PostgreSQL-native `xmin`; generated legacy `bytea` tokens keep only the immediately preceding tenant-aware model fenced until a later contract migration.
- The compatibility migration synchronizes the physical `security_scan_jobs.Version` and `JobVersion` counters bidirectionally. This is a column-level bridge for tenant-schema-compatible clients, not support for running the known pre-tenant binary.
- `SSH.NET` is pinned exactly to `2026.0.0`; the latest resolved direct/transitive package audit reports no vulnerable packages.

## Verification

Current verified inventory:
- **795/795 unit tests passed**.
- **106/106 integration tests passed**, including all **9 PostgreSQL-only** `CampaignSchedulerRaceTests`.
- **901 total backend tests passed**; 97 integration tests remain runnable without PostgreSQL.

Environment-independent commands:
```powershell
dotnet test "tests/Platform.UnitTests/Platform.UnitTests.csproj" --nologo
dotnet test "tests/Platform.IntegrationTests/Platform.IntegrationTests.csproj" --nologo --filter "FullyQualifiedName!~CampaignSchedulerRaceTests"
npm --prefix "frontend/dashboard" run lint
npm --prefix "frontend/dashboard" run build
```

Full PostgreSQL race command:
```powershell
$env:TEST_POSTGRES_ALLOW_DATABASE_DROP = "true"
$env:TEST_POSTGRES_CONNECTION_STRING = "Host=localhost;Port=5432;Database=apihunter_race_0123456789abcdef0123456789abcdef;Username=<test-role>;Passfile=<absolute-path-to-pgpass.conf>"
dotnet test "tests/Platform.IntegrationTests/Platform.IntegrationTests.csproj" --nologo --filter "FullyQualifiedName~CampaignSchedulerRaceTests"
Remove-Item Env:TEST_POSTGRES_CONNECTION_STRING
Remove-Item Env:TEST_POSTGRES_ALLOW_DATABASE_DROP
```

An external target is accepted only when the destructive opt-in equals `true` and the database name matches `^apihunter_race_[0-9a-f]{32}$`. The fixture applies the full migration chain, drops and recreates that approved database, then deletes it after each test. Without an explicit connection, it uses an isolated Testcontainer. The latest run passed all nine PostgreSQL tests on an isolated PostgreSQL 18.4 cluster, including deterministic races, pre/post-commit provider-failure handling, bidirectional scan-job counter fencing, legacy `bytea` rotation, stale-`xmin` writers, non-vacuous timestamp precision, and unrelated-error isolation. Docker/Compose/image execution remains blocked because Docker is not installed; no live scanner/container claim is made. See [`docs/IMPLEMENTATION_STATUS.md`](./docs/IMPLEMENTATION_STATUS.md) for exact evidence.

## Developer documentation
- [Scanner extension guide](./docs/scanner-development/README.md)
- [Provider validation matrix](./docs/PROVIDER_VALIDATION_MATRIX.md)
- [Scan execution architecture](./docs/architecture/scan-execution.md)
- [Scanner worker operations](./docs/operations/scanner-worker.md)
- [Architecture decisions](./docs/DECISIONS.md)
