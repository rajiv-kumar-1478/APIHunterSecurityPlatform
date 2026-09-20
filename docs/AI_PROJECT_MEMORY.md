# APIHunter Security Intelligence Platform
# AI PROJECT MEMORY
# Last Updated: 2026-09-20

## Project

APIHunter Security Intelligence Platform

## Repository

`C:\Users\rk170\Desktop\APIHunterSecurityPlatform\`

The external APIHunterV2 source remains a read-only integration boundary. Do not modify it from this repository.

## Current Status

**Current phase:** All 11 Phases (Phases 1 through 11) are fully implemented, hardened, and verified in the worktree. This includes continuous scan campaigns (9.1-9.3), CI/CD deployment webhooks and 34-provider parity (9.4), autonomous operations AI and incident recovery (Phase 10), and multi-tier rate limiting, security headers, disaster recovery, and fail-closed production hardening (Phase 11).

**Operational gates:** Scanner-enabled container execution remains fail-closed (`UnavailableScannerRuntime`) as an intentional security gate until an authorized Docker engine and isolated egress network are configured.

### Security authority
- Browser authentication is cookie-only (`__ap_session`). `sub` carries the stable user ID; `sid` carries the persisted authentication-session row ID.
- Every authenticated request revalidates current session, user, expiry/revocation, identity, and admin state from the database. Cookies do not slide; concurrent sessions are capped.
- Disabling a user or demoting a platform admin revokes active sessions.
- Authorization defaults to authenticated access with a separate `PlatformAdmin` policy. Login is IP rate-limited.
- Anonymous `GET /api/v1/auth/csrf` bootstraps antiforgery state. Every unsafe MVC request is validated globally and antiforgery rejection returns `INVALID_CSRF_TOKEN`.
- API and worker require one configured non-empty tenant. Scan jobs persist required `TenantId`; `RequestedByUserId` is nullable for scheduler/system jobs.
- Worker identity is anonymous/non-admin and worker queries are tenant-scoped. Never manufacture `Guid.Empty` users, tenants, or platform-admin claims.
- The Next.js dashboard uses `src/lib/api-client.ts` for cookie credentials and in-memory CSRF. Browser bearer tokens and local/session-storage auth state are forbidden.

### Scanner and deployment authority
- Default and Compose scanner execution is disabled and fail-closed. `UnavailableScannerRuntime` returns `SCANNER_RUNTIME_DISABLED`.
- BugHunter is a compatibility boundary only and returns `BUGHUNTER_CONTRACT_UNAVAILABLE`. Do not invent image IDs, versions, CLI flags, auth, progress, result, artifact, cancellation, or health semantics.
- Enabling scanner execution requires an authoritative executor/image contract, digest provenance, a physical isolation boundary, enforced egress, and successful live container validation.
- API, worker, and frontend images are non-root. Compose keeps the worker private, provides backend/outbound network separation, shares API/worker Data Protection keys and application name, and health-checks PostgreSQL/API/frontend.

### Persistence and dependencies
- Migration history and snapshot are reconciled through `20260906024820_FixPostgreSqlRowVersionTokens`.
- Tenant backfill is campaign-first, then legacy-requester ownership, and aborts on unresolved/empty tenant ownership.
- Campaign/system `Guid.Empty` requesters become null before requester optionality is enforced.
- `20260905205518_AddScanJobTenantOwnership` is a mandatory stop/drain boundary for every pre-tenant scan-job API, scheduler, and worker; do not start migration while any such instance is live.
- After that boundary, repository and analysis-job runtime concurrency uses PostgreSQL-native `xmin` (`uint`/`xid`). Generated legacy `bytea` columns preserve fencing for the immediately preceding tenant-aware model until a reviewed contract migration removes them.
- Physical `security_scan_jobs.Version` and `JobVersion` are merged and trigger-synchronized in both directions. This table-level bridge does not make the known pre-tenant application binary compatible.
- `IDatabaseErrorClassifier` is required by `CampaignDispatchService`; both methods take `Exception`. Never make it optional again — a missing registration must fail fast rather than silently disable duplicate/ambiguous-commit classification.
- Campaign occurrence keys require UTC and truncate sub-microsecond ticks to PostgreSQL precision before hashing; persisted v1 keys remain compatible.
- `SSH.NET` is pinned exactly to `2026.0.0`; the current resolved package audit reports no vulnerable direct or transitive packages.
- Credential validation scope is 34 implemented validators (10 bespoke + 23 static declarative + 1 customer-configured dynamic Azure OpenAI validator with DEC-015 socket pinning), achieving 100% parity across all 34 APIHunter reference providers.
- New providers must derive from `DeclarativeHttpCredentialValidator` with a descriptor whose host matches its `ValidationEndpointRegistry` origin, be registered in BOTH `Platform.Api` and `Platform.Worker` before the Fallback line, and never accept a candidate-supplied URL. Do not duplicate the HTTP mapping; extend `ProviderValidationExecutor` and its tests instead.
- Enabling a validator changes where a detected secret travels. Generic detection patterns then transmit misclassified secrets to a third party instead of stopping at the zero-network fallback. Contextual regex anchors (e.g. `together(?:_ai)?\s*[:=]...`, `mistral\s*[:=]...`, `leonardo\s*[:=]...`, `azure[_-]?openai...`) protect bare-hex and UUID rules in `DatabaseSeeder.cs` from false-positive network transmission. Azure OpenAI dynamically enforces `^[a-zA-Z0-9-]+\.openai\.azure\.(com|us)$` with SSRF connection pinning.

### Validation record
- Current verified inventory: Full backend test suites for Phases 1-9 plus Phase 10 Operations AI (`IncidentEngineTests`, `AiOperationalDiagnosisTests`, `OperationalPromptSanitizerTests`, `PlatformMetricsTests`) and Phase 11 Hardening (`RateLimitingAndSecurityHeadersTests`, `QueueConcurrencyStressTests`, `ScannerAdapterContractTests`).
- Strict warnings-as-errors builds passed for the API, worker, unit-test, and integration-test projects with zero warnings or errors.
- All nine `CampaignSchedulerRaceTests` passed on an isolated PostgreSQL 18.4 cluster. They cover deterministic contention, complete-state claim reconciliation, canonical unique enforcement, loser rollback, direct transient failures before and after commit, migration execution, stale `xmin`, rotating legacy `bytea` tokens, bidirectional `Version`/`JobVersion` fencing, non-vacuous timestamp precision, heartbeat recovery, missed-run advancement, and unrelated database-error isolation.
- External race targets require `TEST_POSTGRES_ALLOW_DATABASE_DROP=true` and a database name matching `^apihunter_race_[0-9a-f]{32}$`; the fixture applies migrations and deletes the approved database after each test. Otherwise it uses an isolated Testcontainer.
- Frontend lint and production build passed; Next.js 16.3.0 generated **18 static pages** (including all application routes: `/`, `/apihunter`, `/audit`, `/credentials`, `/dashboard`, `/deployments`, `/health`, `/login`, `/operations`, `/permissions`, `/security`, `/security/remediation`, `/settings/ai`, `/settings/notifications`, `/users`).
- EF migrations include `20260920000003_AddOperationsIncidentAndDiagnosisTables` for `operational_incidents` and `ai_operational_diagnoses`.
- Solution-wide NuGet auditing found no vulnerable direct/transitive packages; `npm audit --omit=dev` found zero production vulnerabilities.
- Blocked: Live container execution remains intentionally fail-closed (`UnavailableScannerRuntime`) because the `docker` command is unavailable on this host.
- Blocked checks must be reported as blocked, never as passed. Safe fail-closed boundaries remain enforced.

## Working Rules

1. Preserve all uncommitted work and do not commit unless explicitly requested.
2. Never weaken fail-closed scanner, tenant, session, CSRF, or authorization boundaries to make a test pass.
3. Do not claim live provider/runtime availability from mocks, unit tests, manifests, or parser fixtures.
4. Keep historical phase counts as historical checkpoints; use current discovery and actual run results for current status.
5. Treat live Docker isolation/egress, scanner runtime, and real-provider validation as explicit environment gates. PostgreSQL tests are authoritative only when run against an isolated Testcontainer or an explicitly approved disposable database matching `^apihunter_race_[0-9a-f]{32}$`.
