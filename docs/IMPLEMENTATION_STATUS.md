# Implementation Status — APIHunter Security Intelligence Platform

Legend:
- `[ ]` Not started
- `[-]` In progress
- `[x]` Completed and verified
- `[!]` Blocked
- `[d]` Deferred

---

## Current Authoritative Status — Phase 9.1 Production Hardening

> The phase sections below are retained as historical checkpoints. Their route and test counts describe the point at which each phase was completed; this section is the current authority.

### Completed in the current worktree
- [x] Browser authentication is cookie-only through `__ap_session`; `sub` is the stable user ID and `sid` is the persisted `AuthenticationSession.Id`.
- [x] Every authenticated request revalidates the session row, expiry/revocation, enabled user state, identity match, and current platform-admin state. Cookies are non-sliding and concurrent sessions are capped.
- [x] User disablement and platform-admin demotion revoke active sessions. Authorization uses an authenticated fallback policy plus the explicit `PlatformAdmin` policy.
- [x] Login is IP rate-limited. Anonymous `GET /api/v1/auth/csrf` bootstraps antiforgery state, and every unsafe MVC request is validated globally with stable `INVALID_CSRF_TOKEN` failures.
- [x] API and worker require one configured non-empty tenant. `SecurityScanJob.TenantId` is durable and required; `RequestedByUserId` is nullable for scheduler/system jobs; worker execution is tenant-scoped and has no synthetic admin authority.
- [x] The dashboard uses one shared cookie/CSRF API client. It sends credentials, stores CSRF state only in module memory, retries once only for explicit antiforgery rejection, and has no bearer/local-storage/session-storage authentication path.
- [x] API, worker, and frontend images run as non-root users. Compose provides a private worker, separate outbound network, shared API/worker Data Protection keys/application name, and PostgreSQL/API/frontend health checks.
- [x] Production/Compose scanner execution fails closed. `UnavailableScannerRuntime` rejects execution with `SCANNER_RUNTIME_DISABLED`; BugHunter returns `BUGHUNTER_CONTRACT_UNAVAILABLE` until authoritative runtime/provider contracts and physical isolation are available.
- [x] Thirty-four credential validators are implemented and registered identically in API and worker: the 10 original bespoke validators, 23 static declarative validators, and 1 customer-configured dynamic validator (`AzureOpenAiCredentialValidator` with per-tenant endpoint allowlisting and `DEC-015` socket-level connection pinning), achieving 100% matrix parity across all 34 APIHunter providers.
- [x] Declarative providers share one tested engine (`ProviderValidationExecutor`) plus a server-controlled `ProviderValidationDescriptor`, so status mapping, rate-limit handling, and evidence sanitization are proven once instead of copied per provider. Tests assert every descriptor host matches its `ValidationEndpointRegistry` origin, since the SSRF handler pins the socket to the registry-resolved address.
- [x] `SSH.NET` is pinned exactly to `2026.0.0`; the resolved direct/transitive NuGet audit reports no vulnerable packages.
- [x] EF migration history and model snapshot are reconciled through `20260906024820_FixPostgreSqlRowVersionTokens`, including guarded tenant backfill, nullable system requester, campaign outcome state, current scanner persistence, native PostgreSQL `xmin`, and tenant-schema-scoped compatibility bridges.
- [x] `20260905205518_AddScanJobTenantOwnership` is an explicit stop/drain boundary for every pre-tenant scan-job API, scheduler, and worker; the later token cutover does not make those binaries schema-compatible.
- [x] **Step 9.4 — Deployment Webhook & Orchestration Wiring** is complete. `RegisteredApplication` (HMAC secret + authorized target URL per CI/CD application) and `DeploymentWebhookRecord` (idempotency log keyed by webhook ID) are new EF-mapped entities with a hand-authored migration (`20260920000001_AddDeploymentWebhookTables`) whose Down is irreversibly blocked at SQLSTATE `0A000`. `DatabaseApplicationTargetResolver` resolves registered applications, decrypts HMAC secrets via ASP.NET Core Data Protection, and records processed IDs only after job creation succeeds. `DatabaseDeploymentScanJobEnqueuer` persists `SecurityScanJob` rows tagged `TriggeredBy=CiCdWebhook` with null `RequestedByUserId` — identical to the campaign-scheduler contract. `InMemoryDeploymentLeaseStore` provides the missing concrete binding for `IDeploymentLeaseStore`, which `DeploymentConcurrencyGate` requires. `DeploymentWebhookController` (`POST /api/v1/webhooks/deployments`) is `[AllowAnonymous]`/`[IgnoreAntiforgeryToken]` with HMAC as the sole auth mechanism; error codes are mapped to 400/401/409/500. All four services are registered as Scoped (resolver and enqueuer respect DbContext lifetime) with `InMemoryDeploymentLeaseStore` as Singleton in both API and Worker `Program.cs`. 16 new unit tests cover `InMemoryDeploymentLeaseStore` (tenant isolation, CRUD) and `DatabaseDeploymentScanJobEnqueuer` (server-authoritative URL, TriggeredBy, null guards, empty-tenant/URL guards, unique IDs).

### Current validation evidence (2026-09-05)
- Verified inventory: **795 unit tests + 106 integration tests = 901 backend tests**, all passing with zero failures or skips. The integration total includes nine real-PostgreSQL `CampaignSchedulerRaceTests`; 97 integration tests remain environment-independent.
- Strict warnings-as-errors builds passed for the API, worker, unit-test, and integration-test projects with zero warnings or errors.
- The PostgreSQL hard gate passed **9/9** against an isolated PostgreSQL 18.4 cluster. A deterministic two-party barrier proves one complete dispatch and one verified `SkippedClaimLost`; additional facts prove migration execution, exact unique-constraint classification, direct transient failures before and after commit, bidirectional `Version`/`JobVersion` fencing, stale-`xmin` rejection, rotating legacy `bytea` tokens, non-vacuous timestamp normalization, and unrelated-error state isolation.
- Migration-based validation exposed and fixed three PostgreSQL-only production defects: invalid non-generated `bytea` row versions, sub-microsecond occurrence-key drift, and an orphaned required `security_scan_jobs.Version` column left by the `JobVersion` transition.
- Atomic dispatch now clears failed tracked writes for wrapped and direct provider exceptions. It suppresses an error only for the canonical unique constraint or a transient unknown-commit outcome when the complete linked job/campaign/audit state is verified.
- `IDatabaseErrorClassifier` is a required dispatch dependency, so a missing registration fails fast instead of silently disabling classification. Both rules are proven directly by `PostgreSqlDatabaseErrorClassifierTests` in addition to the PostgreSQL gate.
- Frontend lint and production build passed; Next.js 16.3.0 generated **16 static pages**, including all 13 application routes plus `/_not-found`.
- EF discovers all 16 migrations through `20260906024820_FixPostgreSqlRowVersionTokens` and reports no pending model changes. Idempotent forward SQL retains generated legacy `RowVersion` columns, synchronizes `Version`/`JobVersion`, and normalizes the occurrence-index name; Down is deliberately irreversible with SQLSTATE `0A000`, and later bridge removal requires a reviewed contract migration after tenant-aware legacy-token instances and their rollback window drain.
- Solution-wide NuGet auditing reports no vulnerable direct/transitive packages in all seven projects; `npm audit --omit=dev` reports zero production vulnerabilities.
- [!] Live Docker/Compose/image validation remains blocked because `docker` is not installed or available on this machine. Scanner runtime, isolation, egress, and real BugHunter availability are therefore not claimed.

---

## Historical Phase Checkpoints

## Phase 1 — Foundation (VERIFIED & LOCKED)

### Solution & Scaffolding
- [x] .NET 10 solution & 6 projects created
- [x] Clean Architecture dependency rules configured
- [x] All NuGet packages added & restored

### Database & Migrations
- [x] PostgreSQL configuration
- [x] PlatformDbContext entity mappings
- [x] EF Core InitialCreate migration generated
- [x] DatabaseSeeder (admin + permissions)

### Authentication & Authorization
- [x] ASP.NET Core Cookie authentication & DB session tracking
- [x] PasswordHasher<User> (Identity)
- [x] Account lockout & IP rate limiting
- [x] CSRF protection (`IAntiforgery` & `X-CSRF-TOKEN`)
- [x] Authenticated fallback, explicit `PlatformAdmin` policy, and audited platform-admin permission override
- [x] Field-level permissions foundation (ALLOW/DENY effects)

### Observability, Health & Notifications
- [x] Serilog structured logging & Correlation ID middleware
- [x] OpenTelemetry tracing & metrics setup
- [x] `IHealthComponent` abstraction
- [x] `SmtpNotificationProvider`, `SendGridNotificationProvider`, `MailgunNotificationProvider`
- [x] Encrypted provider config & health check endpoints

---

## Phase 2 — APIHunter Adapter & Discovery Synchronization (COMPLETED & VERIFIED)

### Schema Inspection & Adapter Architecture
- [x] Inspected actual `APIHunterV2` repository models (`APIKey.cs`, `RepoReference.cs`, `SearchQuery.cs`, `master_init.sql`)
- [x] Created `docs/APIHUNTER-SCHEMA.md` documenting table structures, types, nullability, relationships, and status enums
- [x] Created `IApiHunterSource` read-only adapter interface in `Platform.Domain`
- [x] Created `IApiHunterStatusMapper` for status integer mapping (`1`=Valid, `7`=ValidNoCredits, `0`=Invalid, `-99`=Unverified, `6`=Error, `other`=Unknown)
- [x] Strongly-typed `ApiHunterSourceOptions` configuration (`APIHUNTER_DATABASE_URL`)

### Platform Import Tables & EF Core Migration
- [x] `ApiHunterRecord` entity & DB mapping
- [x] `ApiHunterRepoReference` entity & DB mapping
- [x] `ApiHunterSyncState` entity & DB mapping
- [x] EF Core migration `AddApiHunterTables` generated

### Synchronization & Key Protection
- [x] `ApiHunterSyncService` incremental batch synchronization (`FetchKeysIncrementalAsync`)
- [x] Key masking (`sk-pr****1234`) for default DTO queries
- [x] AES/Data Protection encryption of raw credentials at rest
- [x] Deduplication of imported keys and repository references on repeated syncs
- [x] Key reveal endpoint with mandatory audit logging (`CredentialRevealed`)

### Health & REST Controller
- [x] `ApiHunterHealthComponent` registered in health check pipeline
- [x] `ApiHunterController` REST endpoints:
  - `GET /api/v1/apihunter/summary` (Source vs. Imported metrics)
  - `GET /api/v1/apihunter/records` (Paginated list with status filtering)
  - `POST /api/v1/apihunter/sync` (Trigger sync action)
  - `POST /api/v1/apihunter/records/{id}/reveal` (Audited raw key reveal)

### Next.js Dashboard UI
- [x] Added `APIHunter Data` tab to dashboard navigation (`Sidebar.tsx`)
- [x] Created `/apihunter` page with metrics grid, status filter tabs, paginated table, sync button, and audited reveal modal

### Automated Test Suite
- [x] `ApiHunterAdapterUnitTests` (Status mapping rules, API type enum mapping)
- [x] `ApiHunterSyncTests` (Incremental sync, deduplication verification, key reveal auditing)
- [x] All 37 unit & integration tests passing (`dotnet test`)
- [x] Next.js production build succeeded (`npm run build` — 9 App Router routes compiled cleanly)

---

## Phase 3 — Repository Acquisition & Indexing (IMPLEMENTED & VERIFIED)

### Domain Architecture & Data Contracts
- [x] Domain entities added (`Repository`, `RepositorySource`, `RepositorySnapshot`, `SnapshotFile`, `CredentialCandidate`, `CandidateOccurrence`, `DetectionRule`, `AnalysisJob`)
- [x] Domain enums added (`AcquisitionStatus`, `AnalysisStatus`, `CandidateStatus`, `JobStatus`, `JobType`, `DiscoveryType`, `RuleSource`, `SkipReason`, Audit event codes)
- [x] Domain contracts defined (`IRepositoryProvider`, `IGitHubCredentialProvider`, `IObjectStore`, `ISecretDetector`)
- [x] `FingerprintUtils` domain value object created for versioned HMAC-SHA256 fingerprinting & context redaction

### Database & Migrations
- [x] EF Core entity mappings configured in `PlatformDbContext`
- [x] `IPlatformDbContext` interface extended with Phase 3 `DbSet<T>` properties
- [x] `DesignTimeDbContextFactory` created for design-time tooling
- [x] `AddPhase3Tables` EF Core migration generated successfully

### Infrastructure Adapters & Security
- [x] `Octokit` (14.0.0) & `AWSSDK.S3` (4.0.102.1) packages verified & restored
- [x] `GitHubAppCredentialProvider` (Installation token refresh) & `GitHubPatCredentialProvider` (PAT fallback)
- [x] `GitHubRepositoryProvider` (Normalized metadata, rate-limit health probe & tarball stream download)
- [x] `S3ObjectStoreAdapter` (AWSSDK.S3) & `FileSystemObjectStore` (Development-only production guard)
- [x] `RegexSecretDetector` (Dynamic rule evaluation, HMAC-SHA256 fingerprinting with key versioning, context redaction, ReDoS protections)

### Application Services & Job Orchestration
- [x] `RepositoryAcquisitionService` (Seeding from APIHunter repo references, tarball archive streaming, path traversal protection, file cataloging)
- [x] `SnapshotService` (Snapshot queries, incremental file hash matching)
- [x] `SecretDetectionService` (Snapshot scanning, HMAC candidate fingerprinting, context redaction, reusable hash occurrence creation)
- [x] `CandidateService` (Candidate listing, triage, audited raw key reveal, raw context purge)
- [x] `JobOrchestrationService` (PostgreSQL `FOR UPDATE SKIP LOCKED` row claiming, heartbeat tracking, exponential backoff retries, stale job sweep)

### Worker Background Services
- [x] `RepositoryAcquisitionWorker` (Durable acquisition execution via `FOR UPDATE SKIP LOCKED`)
- [x] `SnapshotAnalysisWorker` (Durable checkpointed analysis worker)
- [x] `StaleJobSweepWorker` (Periodic stale heartbeat sweeper & auto-recovery)

### API, Health & Dashboard UI
- [x] API Controllers (`RepositoryController`, `SecretCandidateController`, `AnalysisJobController`, `DetectionRuleController`)
- [x] DatabaseSeeder extended with ~20 high-confidence built-in detection rules & Phase 3 permissions

## Phase 4 — AI Repository Investigation & Security Intelligence Graph (COMPLETED & VERIFIED)

### Step 5: Staged AI Repository Investigation Engine & Worker (COMPLETED & VERIFIED)
- [x] Implemented `AiInvestigationEngine` in `src/Platform.Infrastructure/Services/AiInvestigationEngine.cs`
- [x] 10-Stage Pipeline: Executes stages sequentially (`RepositoryMetadata`, `FileInventory`, `TechnologyIdentification`, `ApiHunterSeedInvestigation`, `ConfigurationAnalysis`, `CandidateDiscovery`, `CrossFileRelationshipAnalysis`, `CredentialServiceRelationshipAnalysis`, `ProductionExposureAnalysis`, `FinalIntelligenceReport`)
- [x] Atomic Worker Lease Fencing (`ClaimToken`): Configured `.IsConcurrencyToken()` on `ClaimToken` in EF Core (`PlatformDbContext.cs`). All worker mutations (heartbeat, stage progress, checkpoint writes, job completion, job failure, pause state) execute SQL UPDATE with `WHERE Id = @Id AND claim_token = @OriginalClaimToken`. If a stale worker attempts a write after a job re-claim, 0 database rows match, triggering `DbUpdateConcurrencyException`, and the mutation is atomically rejected (`SaveWithLeaseCheckAsync` returns `false`)
- [x] Complete Resource Limits Enforced (`AiInvestigationEngineOptions`):
  - `MaxFilesPerInvestigation`: 50 files
  - `MaxFileSizeBytes`: 1 MB
  - `MaxAiCallsPerInvestigation`: 20 calls
  - `MaxTokensPerInvestigation`: 100,000 tokens
  - `MaxStageRetries`: 3 retries per stage
  - `MaxInvestigationDurationMinutes`: 30 minutes
- [x] Three Discovery Sources Preserved: `ApiHunterSync` (APIHunter seed provenance), `DeterministicDetector` (Phase 3 RegexSecretDetector baseline safety net), and `AiInvestigator` (Phase 4 contextual discovery) remain distinct and fully queryable
- [x] Strict Semantic Boundaries: Regex matches, AI candidates, and occurrences remain `Unverified` or `Candidate` status in Phase 4. Zero auto-promotion to `Valid` status prior to Phase 5 credential validation
- [x] Restart-Safe Checkpointing: Stage completion persists `AiInvestigationCheckpoint` with `DurableResultJson`. Worker crashes/restarts resume from uncompleted stage without re-executing finished stages
- [x] Single-Concurrency Worker: Implemented `AiInvestigationWorker` (`BackgroundService`) in `src/Platform.Infrastructure/Workers/AiInvestigationWorker.cs` with atomic job claiming (`WorkerId`, `ClaimToken`, `LastHeartbeatAtUtc`) and Concurrency = 1
- [x] APIHunter Seed Integration: Supports repository seeds from APIHunter `Valid` & `ValidNoCredits` while preserving APIHunter status as immutable provenance
- [x] Raw Secret Protection: Prompts sent to AI adapters contain masked values (`****1234`) and file context — raw secrets are NEVER sent to AI
- [x] Idempotent Evidence Storage: `AiInvestigationEvidence` records deduplicated using deterministic SHA-256 `Fingerprint` (`SnapshotId:EvidenceType:FilePath:StartLine:EndLine`)
- [x] Global Pause Check: Pauses execution safely at stage boundary when `ai.global_enabled = false` without corrupting state or purging queued jobs
- [x] `AiInvestigationService` implemented in `src/Platform.Application/Services/AiInvestigationService.cs` with job deduplication (`TriggerInvestigationAsync`), pause, resume, cancel, and details query
- [x] `AiInvestigationController` API implemented in `src/Platform.Api/Controllers/AiInvestigationController.cs` (`POST /api/v1/ai/investigations`, `GET /api/v1/ai/investigations/{id}`, `POST /api/v1/ai/investigations/{id}/pause|resume|cancel`)

### Step 6: Security Intelligence Graph & Edge Builder (COMPLETED & VERIFIED)
- [x] Implemented `SecurityIntelligenceGraphBuilder` in `src/Platform.Application/Services/SecurityIntelligenceGraphBuilder.cs`
- [x] Node & Edge Identity Strategy: Nodes deterministically indexed on `(NodeType, Name)`; Edges deterministically indexed on `(SourceNodeId, TargetNodeId, EdgeType)` (`DEC-013`)
- [x] Node Types Supported: `Repository`, `CredentialCandidate`, `Service`, `Domain`, `Database`, `Environment`
- [x] Safe Entity Normalization: Schemes/ports/paths stripped from domains (`https://EXAMPLE.COM/api` $\rightarrow$ `example.com`), service names lower-kebabed (`web_api` $\rightarrow$ `web-api`), environments normalized (`prod`/`live` $\rightarrow$ `production`). Raw secrets are NEVER used in node keys or labels
- [x] Multi-Source Provenance Preservation: Edges preserve `DiscoverySource` (`ApiHunterSync`, `DeterministicDetector`, `AiInvestigator`). Multiple discovery layers enrich existing edges (`LastObservedAtUtc`, upgraded `Confidence`, appended evidence references) rather than creating duplicate edges
- [x] Historical Observation Tracking: `FirstObservedAtUtc` and `LastObservedAtUtc` recorded on nodes and edges to maintain historical context across commit snapshots
- [x] `SecurityIntelligenceService` implemented in `src/Platform.Application/Services/SecurityIntelligenceService.cs` supporting graph queries (`GetGraphAsync`), paginated nodes (`GetNodesAsync`), node details & relationships (`GetNodeByIdAsync`, `GetNodeRelationshipsAsync`), paginated edges (`GetEdgesAsync`), and admin rebuilds (`RebuildGraphForRepositoryAsync`)
- [x] `SecurityIntelligenceController` API implemented in `src/Platform.Api/Controllers/SecurityIntelligenceController.cs` (`GET /api/v1/intelligence/graph`, `GET /api/v1/intelligence/nodes`, `GET /api/v1/intelligence/nodes/{id}`, `GET /api/v1/intelligence/nodes/{id}/relationships`, `GET /api/v1/intelligence/edges`, `POST /api/v1/intelligence/graph/rebuild`)
- [x] Unit Tests: Created `SecurityIntelligenceGraphTests` covering node/edge identity, normalization, multi-source provenance enrichment, historical tracking, and API service queries
- [x] Test Suite execution: **109 / 109 Automated Tests Passed** (103 Unit + 6 Integration, 0 Failures)

## Phase 5 — Credential Validation Engine (FULLY IMPLEMENTED & LOCKED — Steps 1–5 Verified)
- [x] Implemented `ValidationStatus` enum (`Unknown`, `Pending`, `Valid`, `ValidInsufficientScope`, `Invalid`, `Expired`, `Revoked`, `RateLimited`, `Unavailable`, `Unsupported`, `BlockedByPolicy`, `ValidationError`)
- [x] Implemented `ValidationConfidence` enum (`Indeterminate`, `Strong`, `Confirmed`)
- [x] Added `JobType.CredentialValidation` reusing existing `AnalysisJob` infrastructure & `.IsConcurrencyToken()` ClaimToken fencing (`DEC-014`)
- [x] Implemented `CredentialValidationResult` database entity & EF Core mapping (`credential_validation_results`)
- [x] Applied EF Core migration `AddPhase5ValidationTables`
- [x] Implemented `ValidationEndpointRegistry` enforcing server-controlled target endpoints for supported providers (`OpenAI`, `Anthropic`, `GitHub`, `AWSIAM`, `Stripe`, `SendGrid`, `Mailgun`, `DeepSeek`, `Groq`, `Slack`). Candidate-supplied URLs/hosts are strictly rejected
- [x] Implemented `SsrfProtectionService` enforcing socket-level IP connection pinning via `SocketsHttpHandler.ConnectCallback` to eliminate DNS rebinding TOCTOU risks (`DEC-015`). Validates ALL IPv4 & IPv6 addresses against private/loopback/cloud-metadata CIDRs (`127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fe80::/10`, `fc00::/7`, `100.64.0.0/10`)
- [x] Verified existing Data Protection mechanism (`IDataProtectionProvider` with purpose `"Platform.SecretCandidate.RawValue"`) used for credential decryption in memory (`DEC-016`)
- [x] Implemented `CredentialValidationService` in `Platform.Application` managing job enqueuing, secret decryption in memory, plugin dispatch, append-only historical records, and CandidateStatus preservation
- [x] Implemented `CredentialValidationWorker` in `Platform.Worker` handling durable job polling, PostgreSQL `FOR UPDATE SKIP LOCKED` claiming, atomic `ClaimToken` fencing, retry policies, and worker recovery
- [x] Implemented `CredentialValidationController` exposing REST APIs (`POST /validate`, `GET /history`, `GET /results/{id}`)
- [x] Implemented 10 Provider Validator Plugins: `OpenAiCredentialValidator`, `AnthropicCredentialValidator`, `DeepSeekCredentialValidator`, `GroqCredentialValidator`, `AwsStsCredentialValidator` (SigV4 signed STS `GetCallerIdentity`), `GitHubCredentialValidator`, `StripeCredentialValidator` (returns `Unsupported` for `whsec_`/`pk_` with zero network calls), `SendGridCredentialValidator`, `MailgunCredentialValidator` (Basic auth `api:{key}`), `SlackCredentialValidator` (inspects JSON `"ok": true`)
- [x] Implemented `FallbackCredentialValidator` returning `ValidationStatus.Unsupported` for non-platform-supported providers with zero network calls
- [x] Extended `DiscoveryType` enum with `CredentialValidation` to preserve cross-source provenance on graph edges (`DEC-017`)
- [x] Enhanced `SecurityIntelligenceGraphBuilder` with `IngestCredentialValidationResultsAsync` dynamically updating candidate node labels (`[Valid]`, `[Invalid]`), metadata (`isCurrentlyValidated`, `latestValidationStatus`), and graph edges while preserving node identity and discovery provenance
- [x] Created `docs/PROVIDER_VALIDATION_MATRIX.md` auditing all 34 APIHunterV2 reference providers, 10 Step 2 MVP providers, 24 deferred providers, and 6 security overrides
- [x] Implemented Next.js 16 Dashboard UI in `frontend/dashboard/src/app/credentials/page.tsx` featuring masked key inventory, validation status badges, rate-limited/unsupported state distinctions, provenance badges, append-only audit history modal, Security Graph topology preview, and admin-only validation triggers
- [x] Updated `Sidebar.tsx` with direct link to `Credentials & Validation` (`/credentials`)
- [x] Created `Phase5FullIntegrationAndSecretLeakTests` and `SecurityIntelligenceGraphValidationEnrichmentTests` verifying zero secret disclosure, status transition logic, graph enrichment, and audit trail safety
- [x] Test Suite execution: **148 / 148 Automated Tests Passed** (142 Unit + 6 Integration, 0 Failures)

- [x] Step 3 — Graph Intelligence Engine (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `GraphIntelligenceEngine` in `src/Platform.Application/Services/GraphIntelligenceEngine.cs` (read-only consumer of graph nodes/edges)
  - [x] Implemented strict repository boundary scoping (`repo:{id}` 1-hop subgraph) to prevent cross-repository finding contamination
  - [x] Implemented canonical finding identity derived from stable graph node `Id` (Guid), not labels (`DEC-018`)
  - [x] Implemented explicit `INTERNET_FACING` edge chain rule (`Domain ←[AssociatedWith]→ Repo ←[BelongsTo]─ Service`)
  - [x] Implemented allowlist-only `SafeEvidenceJson` projection for graph node/edge evidence
  - [x] Enforced zero direct dependency on `RiskEngine`; all finding/evidence updates flow through `SecurityFindingService`
  - [x] Added `GraphIntelligenceAnalysisCompleted` audit event code to `DomainEnums.cs`
  - [x] Added `AnalyzeGraphIntelligenceAsync` method to `SecurityIntelligenceService.cs` with audit logging
  - [x] Registered `GraphIntelligenceEngine` in DI (`Program.cs`)
  - [x] Created `GraphIntelligenceEngineTests` covering 11 test cases (4 patterns, idempotency, evidence FK correctness, secret-leak defense, empty graph safety, risk factor integration, cross-repo isolation, and identity stability)
  - [x] Test Suite execution: **169 / 169 Automated Tests Passed** (163 Unit + 6 Integration, 0 Failures)

- [x] Step 4 — Multi-Snapshot Exposure Analysis (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `ExposureAnalysisService` in `src/Platform.Application/Services/ExposureAnalysisService.cs` (read-only analysis layer)
  - [x] Implemented multi-snapshot persistence detection ($\ge 2$ distinct `CommitSha` snapshots) emitting `HistoricalExposureDetected` findings
  - [x] Implemented canonical finding identity derived from candidate ID (`CoreEntityId = candidate.Id.ToString("N")`)
  - [x] Implemented occurrence-granular `HistoricalCommit` evidence fingerprinting (`SourceEntityId = $"historical:{candidateId:N}:{snapshotId:N}:{snapshotFileId:N}:{lineNumber}"`)
  - [x] Enriched existing `ValidatedCredentialExposed` and `UnvalidatedCredentialExposed` findings with `HistoricalCommit` evidence
  - [x] Enforced zero direct dependency on `RiskEngine`; all finding and evidence updates flow through `SecurityFindingService`
  - [x] Implemented allowlist-only `SafeEvidenceJson` projection (commit SHA, acquired date, file path, line number, masked value)
  - [x] Preserved `CredentialCandidate.Status` immutability
  - [x] Added `AnalyzeSnapshotExposureAsync` method to `SecurityIntelligenceService.cs`
  - [x] Registered `ExposureAnalysisService` in DI (`Program.cs`)
  - [x] Created `ExposureAnalysisServiceTests` unit test suite (10 test cases)
  - [x] Test Suite execution: **179 / 179 Automated Tests Passed** (173 Unit + 6 Integration, 0 Failures)

- [x] Step 5 — Finding Lifecycle Governance (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `SecurityFindingLifecycleService` for human-governed finding status transitions (`Confirmed`, `Remediated`, `AcceptedRisk`, `FalsePositive`, `Resolved`, `Open/Reopen`)
  - [x] Enforced **Option A contract**: resolution fields (`ResolvedAtUtc`, `ResolvedByUserId`, `ResolutionReason`) populated ONLY when `FindingStatus.Resolved`
  - [x] Enforced mandatory `Reason` parameter for all status transitions; `ResolutionReason` required for `Resolved` status
  - [x] Implemented `LifecycleVersion` optimistic concurrency guard (`IsConcurrencyToken`), rejecting stale version edits (`409 Conflict`)
  - [x] Implemented append-only `SecurityFindingStatusHistory` audit trail tracking status transitions, actor, timestamp, and reason
  - [x] Preserved `CredentialCandidate.Status` immutability and `RiskEngine.cs` purity
  - [x] Created `SecurityFindingLifecycleServiceTests` unit test suite (9 test cases)
  - [x] Test Suite execution: **194 / 194 Automated Tests Passed** (188 Unit + 6 Integration, 0 Failures)

- [x] Step 6 — Continuous Revalidation (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `ContinuousRevalidationWorker` background service polling overdue candidates based on `MinRevalidationIntervalHours`
  - [x] Implemented `ValidationStateChangeProcessor` processing validation results atomically with PostgreSQL `FOR UPDATE SKIP LOCKED` claim token fencing
  - [x] Added separate `FindingType.ExpiredCredentialExposed` and `FindingType.RevokedCredentialExposed` for refined alerting semantics
  - [x] Implemented transient result exclusion (`RateLimited`, `Unavailable` results excluded from state-change detection and processed timestamp updates)
  - [x] Implemented two-timeline rule: recent transient result does NOT suppress overdue revalidation when definitive validation is overdue
  - [x] Enforced zero automatic finding status transitions; finding lifecycle state remains human-governed
  - [x] Created `ValidationStateChangeProcessorTests` unit test suite (21 test cases)
  - [x] Test Suite execution: **215 / 215 Automated Tests Passed** (209 Unit + 6 Integration, 0 Failures)

- [x] Step 7 — Alerting & High-Fidelity Notifications (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `SecurityAlertService` decision engine with fail-closed configuration (`SecurityAlertOptions.GlobalEnabled` defaults to `false`)
  - [x] Implemented database-backed atomic claim protocol (`SecurityAlertLog` lease) using canonical fingerprint (`finding:` or `repository:`) to prevent duplicate alerts under concurrency
  - [x] Implemented 60-minute alert cooldown window suppressing repeated notifications within cooldown window (`AuditEventCode.AlertSuppressedByCooldown`)
  - [x] Triggered high-fidelity alerts on explicit `Revoked`/`Expired` events, Critical score threshold crossing ($\ge 80$), High threshold crossing ($< 60 \rightarrow \ge 60$), risk jump delta ($\Delta \ge 25$), and new High/Critical findings
  - [x] Formatted secret-safe HTML/text notification templates strictly rendering `MaskedValue` (`sk-proj-****1234`) and dispatched via Phase 1 `INotificationService`
  - [x] Created `SecurityAlertServiceTests` unit test suite (10 test cases including concurrent `Task.WhenAll` atomic claim tests)
  - [x] Test Suite execution: **225 / 225 Automated Tests Passed** (219 Unit + 6 Integration, 0 Failures)

- [x] Step 8 — Security Center UI Dashboard Integration (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `SecurityCenterController` exposing read-only `GET /api/v1/security-center/posture` (reads persisted `RepositoryRiskScore` DB rows) and `GET /api/v1/security-center/alerting-status` (sanitized read-only DTO without secrets)
  - [x] Added `/security` ("Security Center") nav item to Next.js dashboard `Sidebar.tsx`
  - [x] Implemented typed frontend API client `security-api.ts` for posture, sanitized alerting status, paginated findings, evidence, status history, and graph endpoints
  - [x] Built modular Next.js dashboard UI (`security/page.tsx`, `SecurityPostureCard.tsx`, `FindingFilters.tsx`, `FindingsTable.tsx`, `RiskBreakdown.tsx`, `EvidenceTimeline.tsx`, `LifecycleTimeline.tsx`, `GovernanceActions.tsx`, `FindingDetailDrawer.tsx`, `SecurityGraphView.tsx`, `AlertingStatusCard.tsx`)
  - [x] Enforced zero client-side risk math; UI strictly displays backend `RiskEngine` scores and factor breakdown DTOs
  - [x] Enforced backend API authorization (`403 Forbidden` on unauthorized status transitions) and optimistic concurrency version guard (`ExpectedLifecycleVersion`)
  - [x] Verified zero raw credential display (`MaskedValue` ONLY)
  - [x] Created `SecurityCenterControllerTests` integration test suite (3 test cases)
  - [x] Next.js frontend build succeeded (`npm run build`)
  - [x] Test Suite execution: **228 / 228 Automated Tests Passed** (219 Unit + 9 Integration, 0 Failures)

- [x] Step 9 — Final Exit Gate (VERIFIED & LOCKED):
  - [x] 0 Build Errors (`dotnet build`)
  - [x] 100% Test Pass Rate (**228 / 228 Automated Tests Passed**)
---

## Phase 7 — Automated Security Response & Remediation (VERIFIED & LOCKED)

- [x] Step 1 — Remediation Action Domain & Governance (FULLY IMPLEMENTED & LOCKED):
  - [x] Created `RemediationAction` and `RemediationActionHistory` domain entities with zero raw secret fields (`ActionFingerprint` unique index, optimistic concurrency `Version`, masked resource target `sk-live-****5678`)
  - [x] Implemented `RemediationActionService` with strict state machine transitions (`Proposed` $\rightarrow$ `PendingApproval` $\rightarrow$ `Approved` / `Rejected` $\rightarrow$ `Executing` $\rightarrow$ `Executed` / `Failed` $\rightarrow$ `VerificationPending` $\rightarrow$ `Verified` / `VerificationFailed`)
  - [x] Created EF Core migration `AddPhase7RemediationActionTables`
  - [x] Test Suite execution: **242 / 242 Automated Tests Passed**

- [x] Step 2 — Deterministic Recommendation Engine (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `RemediationRecommendationEngine` with 100% pure deterministic rules (Revoke Credential, Rotate Key, Update Auth Config)
  - [x] Zero direct `RiskEngine` or infrastructure dependencies
  - [x] Created `RemediationRecommendationEngineTests` unit test suite
  - [x] Test Suite execution: **260 / 260 Automated Tests Passed**

- [x] Step 3 — Response Policy Engine (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `ResponsePolicyEngine` evaluating environment limits, high-risk flags, and configurable action proposal caps
  - [x] Pure deterministic evaluation; audit logging performed at service orchestration layer
  - [x] Test Suite execution: **279 / 279 Automated Tests Passed**

- [x] Step 4 — Approval & Authorization Workflow (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `RemediationApprovalService` enforcing RBAC (`remediation.approve`/`remediation.manage` / `IsPlatformAdmin`), authenticated actor binding, lease validation, active finding checks, and optimistic concurrency version control
  - [x] Test Suite execution: **297 / 297 Automated Tests Passed**

- [x] Step 5 — Remediation Execution Engine (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `RemediationExecutionService` with `IProtectedCredentialResolver` secret-resolution boundary (in-memory raw secret scope only)
  - [x] Atomic execution claim token acquisition (`ExecutingClaimToken`), EF Core migration `AddPhase7RemediationExecutionTables`, and `GitHubRemediationProvider` / `SafeFallbackRemediationProvider` adapters
  - [x] Test Suite execution: **322 / 322 Automated Tests Passed**

- [x] Step 6 — Post-Remediation Verification Engine (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `PostRemediationVerificationService` with `VerificationClaimToken` atomic claim and 10-minute stale claim recovery
  - [x] Reused existing Phase 5/6 credential revalidation pipeline (`CredentialValidationResult`) without creating a second validator
  - [x] Recalculated post-remediation risk via `SecurityFindingService`; preserved `RiskEngine.cs` purity and finding lifecycle status immutability
  - [x] Created EF Core migration `AddPhase7RemediationVerificationTables`
  - [x] Test Suite execution: **346 / 346 Automated Tests Passed**

- [x] Step 7 — Remediation Center UI & Governance Dashboard (FULLY IMPLEMENTED & LOCKED):
  - [x] Implemented `RemediationController` exposing sanitized REST DTOs (`RemediationActionListDto`, `RemediationActionDetailDto`, `RemediationActionHistoryDto`, `RemediationVerificationDto`, `RemediationSummaryDto`)
  - [x] Version-aware mutation endpoints (`/approve`, `/reject`, `/execute`, `/verify`) returning `409 Conflict` on version mismatch
  - [x] Built Next.js Remediation Center UI (`RemediationSummary`, `RemediationFilters`, `RemediationTable`, `RemediationDetailDrawer`, `RemediationApprovalPanel`, `RemediationExecutionStatus`, `RemediationVerificationPanel`, `RemediationTimeline`, `remediation/page.tsx`)
  - [x] Clean Next.js production build (`npx next build`) with 0 errors
  - [x] Created `RemediationControllerTests` integration test suite
  - [x] Test Suite execution: **366 / 366 Automated Tests Passed**

- [x] Step 8 — Final Exit Gate & Lock (FULLY VERIFIED & LOCKED):
  - [x] Gate 1 (Backend Build): 0 errors
  - [x] Gate 2 (Backend Test Suite): 100% pass rate (366/366 passed, 0 failures)
  - [x] Gate 3 (Frontend Build): 0 build/type errors
  - [x] Gates 4–16 (Migrations, Secret Safety, Authorization, Concurrency, Lease Expiry, Finding Governance, Verification Authority, Risk Boundary, Audit Trail, Core Engine Isolation, `APIHunterV2` Isolation, Documentation) passed
  - [x] Gate 17 (Phase Lock): **Phase 7 OFFICIALLY LOCKED**

---

## Phase 8 — Hosted Security Scanning & Scan Foundation (VERIFIED & LOCKED)

- [x] Step 1 — Scan Tool Registry & Security Target Governance (VERIFIED & LOCKED):
  - [x] Created `SecurityScanTool`, `SecurityTarget`, `SecurityScanJob`, and `ScanProviderAccount` entities with DB mappings and migrations.
  - [x] Implemented `ScanToolRegistryService` and `ScanJobService` with capability parsing, authorization boundaries, and profile mappings.
  - [x] Implemented `BugHunterScanProvider` and in-memory/configuration secret stores.

- [x] Step 2 — Fail-Closed Egress Policy Engine (VERIFIED & LOCKED):
  - [x] Implemented `EgressPolicyEngine` evaluating URI syntax, DNS resolution, private IP ranges (RFC 1918), link-local/IMDS (`169.254.169.254`), loopback (`127.0.0.0/8`, `::1`), and DNS rebinding mitigations.
  - [x] Created `EgressTarget` records with immutable policy versions and time-to-live expirations.

- [x] Step 3 — CLI Tool Adapter & Orchestration Engine (VERIFIED & LOCKED):
  - [x] Implemented `GenericCliToolAdapter` with strict executable allowlists (`ValidateToolExecutableWhitelist`), argument sanitization, platform scratch directory validation, and clean child process tree termination.
  - [x] Implemented `GenericScanWorker` orchestrating jobs fail-closed.

- [x] Step 3B.4 — Production-Hardened Scanner Runtime Sandbox & Egress Boundary (VERIFIED & LOCKED - Commit `e655acc`):
  - [x] Enforced Egress Gateway (`IEnforcedEgressGateway` & `EnforcedEgressGateway`) with dedicated network attachment (`apihunter-sandbox-net`), gateway proxies (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`), and `NO_PROXY=""`.
  - [x] Immutable container image provenance verification (`ContainerImageRepository` allowlisting and strict `ContainerImageDigest` `sha256:...` pinning) with zero `:latest` fallback.
  - [x] Strict sandbox invariant: `GenericScanWorker` mandates `IScannerRuntimeSandbox` with zero direct host process fallbacks.
  - [x] Authoritative Docker daemon health via `docker info` and live bounded cloud health probe (`GET /health/ready` with 3s timeout and `X-Scanner-Service-Key`).
  - [x] `DevelopmentHostScannerRuntime` created strictly for dev/test harnesses with production startup guard.
  - [x] Synchronized `PlatformScratchRoot` between worker and runtime sandbox.
  - [x] Compiler gate: `dotnet build -warnaserror` (0 warnings, 0 errors).
  - [x] Automated test suite: **503 / 503 Tests Passed (100%)**.

- [x] Step 3B.5 — Deployment Validation Pass & Operational Observability (VERIFIED & LOCKED - Commit `b4ff952`):
  - [x] Step 3B.5.1 (Deployment Contracts): Verified strongly-typed configuration contracts for `LocalDocker` and `CloudManagedContainer`, environment variable binding, and secret sanitization (`X-Scanner-Service-Key` never exposed in health DTOs).
  - [x] Step 3B.5.2 (Network Topology & Boundary Verification): Built `EnforcedEgressProxyServer` and verified real socket proxy interception, blocking loopback (`127.0.0.1`), RFC 1918 private subnets (`10.x`, `172.16-31.x`, `192.168.x`), IMDS (`169.254.169.254`), unapproved external IPs, and DNS rebinding attacks at connection time.
  - [x] Step 3B.5.3 (Observability, Telemetry & Dashboard Health): Implemented granular status categories (`Healthy`, `Degraded`, `Unavailable`, `NotConfigured`, `FailClosed`), diagnostic breakdown, and frontend dashboard runtime readiness badge (`ReadyForScans`).
  - [x] Compiler gate: `dotnet build -warnaserror` (0 warnings, 0 errors) & Frontend Next.js production build (`npm run build` with 0 errors).
  - [x] Automated test suite: **517 / 517 Tests Passed (100%)**.

- [x] Step 4.1 — Scan Profile Capability Matrix & Tool Selection (VERIFIED & LOCKED):
  - [x] Implemented `ScanProfileMatrix` defining `Discovery`, `Probing`, and `Assessment` phases for `Recon`, `Standard`, and `Deep` profiles.
  - [x] Dynamic tool resolution matching profile capability requirements against registered security tools.

- [x] Step 4.2 — Multi-Tool Scan Execution Orchestrator (VERIFIED & LOCKED):
  - [x] Implemented `ScanExecutionOrchestrator` coordinating sequential tool runs, fail-closed isolation, scratch directory isolation, and bounded execution timeouts.

- [x] Step 4.3 — Output Parsers & Data Normalization (VERIFIED & LOCKED):
  - [x] Implemented `IToolOutputParserProvider` and parsers for Nuclei, Katana, FFuF, and Nmap/Naabu.
  - [x] Standardized tool outputs into normalized `FindingCandidate` records.

- [x] Step 4.4 — Finding Ingestion & Risk Scoring Pipeline (VERIFIED & LOCKED):
  - [x] Implemented `ScanFindingIngestionEngine` with candidate validation, URL/evidence sanitization, deduplication against Phase 6 finding inventory, and deterministic risk score computation.

- [x] Step 4.5 — Provenance & Immutable Execution Receipts (VERIFIED & LOCKED - Commit `6f55ffb`):
  - [x] Added `ScanExecutionReceipt` and `ToolExecutionReceipt` records with immutable SHA-256 container digests and execution timelines.
  - [x] Fatal sandbox failure propagation and downstream tool skipping.

- [x] Step 4.6 — Tenant Authorization, Cancellation & Concurrency (VERIFIED & LOCKED - Commit `26fbb7a`):
  - [x] Enforced strict tenant isolation (HTTP 403 Forbidden for cross-tenant access/mutation).
  - [x] Cooperative cancellation tokens propagated to running sandbox containers.
  - [x] Concurrency retry recovery and target re-authorization on retry.

- [x] Step 4.7 — Result Lifecycle, Scan Diff & Multi-Format Reporting (VERIFIED & LOCKED - Commit `5bf6a18`):
  - [x] Step 4.7 Part 1: Implemented `ScanFindingObservation` with `UNIQUE(FindingId, ScanJobId)`, `ScanPostExecutionProcessor`, capability-aware `DetermineFullCoverage`, 2-consecutive-scan absence resolution rule, baseline comparison (`ScanDiff`), and `Proposed` Phase 7 remediation hand-off.
  - [x] Step 4.7 Part 2: Implemented `CanonicalSecurityReport` authoritative model, pure projection formatters (`Json`, `Sarif` 2.1.0, `Markdown`, `Html`), checked-in official OASIS SARIF 2.1.0 schema fixture, deterministic provenance signature over immutable scan metadata, and enforced 20 MiB output ceiling (`HTTP 413 Payload Too Large`).

- [x] Step 4.8 — End-to-End Production-Pipeline Acceptance Pass (FULLY IMPLEMENTED & VERIFIED):
  - [x] Full pipeline acceptance test: Target & Job Creation $\rightarrow$ `ScanExecutionOrchestrator` $\rightarrow$ Sandboxed tool execution (raw stdout) $\rightarrow$ `IToolOutputParserProvider` $\rightarrow$ `FindingCandidate` $\rightarrow$ `ScanFindingIngestionEngine` $\rightarrow$ `RiskEngine` $\rightarrow$ EF Core Database Ingestion $\rightarrow$ `ScanExecutionReceipt` with valid 64-character SHA-256 container digests $\rightarrow$ `ScanPostExecutionProcessor` $\rightarrow$ `ScanDiff` $\rightarrow$ `ScanReportBuilderService` $\rightarrow$ 4 Format Projections (`Json`, `Sarif` 2.1.0, `Markdown`, `Html`).
  - [x] SARIF output evaluated and verified compliant with checked-in official OASIS SARIF 2.1.0 JSON Schema fixture.
  - [x] Multi-scan lifecycle progression verified: 1 absence $\rightarrow$ `NotObserved`, 2 consecutive absences $\rightarrow$ `Resolved`.
  - [x] Strict tenant isolation verified: Cross-tenant access blocked at all endpoints with HTTP 403 Forbidden.
  - [x] Secret sanitization: Live token redaction pattern in `EvidenceSanitizer` preventing leakages in all report formats.
  - [x] Resource limits: 1,000 findings, 10 MiB evidence, and 20 MiB output ceiling enforced.
  - [x] Fixture hardening: Sourced scratch directory from `ScannerRuntimeOptions.PlatformScratchRoot` and verified path boundary invariants.

- [x] Step 4.9 — Deployment-Level Security Acceptance Pass (FULLY IMPLEMENTED & VERIFIED):
  - [x] Gate 1: Docker Runtime Sandbox Invariant & Fallback Prohibition — `DockerScannerRuntime` verified with read-only root, dropped capabilities, no-new-privileges, and fail-closed error handling (`DOCKER_RUNTIME_UNAVAILABLE`).
  - [x] Gate 2: Image Provenance & Container Image Digest Pinning — Rejects unpinned images and `:latest` tags with `TOOL_PROVENANCE_NOT_VERIFIED`.
  - [x] Gate 3: Egress Gateway Socket Proxy Enforcement — Real socket connections verified; proxy blocks loopback (`127.0.0.1`), IMDS (`169.254.169.254`), and RFC 1918 private subnets (`10.0.0.1`) with `403 Forbidden`.
  - [x] Gate 4: Cancellation Propagation — Aborts running sandbox container/process immediately upon cancellation token signal.
  - [x] Gate 5: Observability & Runtime Readiness — Granular categories (`Healthy`, `Degraded`, `Unavailable`, `NotConfigured`, `FailClosed`) verified without secret leakage.
  - [x] Automated Test Suite: **586 / 586 Automated Tests Passed (100%)** with 0 warnings (`-warnaserror`).
  - [x] Next.js Dashboard: Production build clean with 0 errors.
  - [x] Phase 8 Status: **PHASE 8 OFFICIALLY LOCKED & COMPLETE**.

---

## Phase 9 — Continuous Security Scan Campaigns (STEPS 9.1–9.3 IMPLEMENTED & VERIFIED)

- [x] Step 9.1 — Campaign & Schedule Contract (FULLY IMPLEMENTED & VERIFIED):
  - [x] Complete Tenant Ownership Chain: `Tenant` $\rightarrow$ `Repository` $\rightarrow$ `SecurityTarget` $\rightarrow$ `ScanCampaign` $\rightarrow$ `SecurityScanJob` validated on creation, update, and execution.
  - [x] Schedule Model: Built deterministic `CampaignScheduleCalculator` supporting `Cron` (standard 5-part syntax evaluated against IANA timezone) and `Interval` ($\ge 15\text{ minutes}$ minimum limit) with explicit DST transition disambiguation.
  - [x] Concurrency Policies: Implemented `SkipIfRunning` (default), `ForbidConcurrent`, and `QueueNext` (strictly capped at queue depth = 1).
  - [x] Optimistic Concurrency: `ScheduleVersion` monotonically incremented on state mutations; stale dispatch protection.
  - [x] Authoritative Database Cursor: `NextRunUtc` serves as the authoritative database scheduler cursor.
  - [x] Audit Logging: Every dispatch, skip, queue, or reject decision persisted to `CampaignExecutionAuditLog` with `SchedulerDecision` enum and diagnostic reasons.
  - [x] REST Controller: `POST`, `GET`, `PUT`, `DELETE` (soft archive), `/pause`, `/resume`, `/run-now`, and `/audit-logs` endpoints on `/api/v1/security/campaigns`.
  - [x] Immutability: Pausing, resuming, or archiving a campaign never mutates or deletes historical scan jobs or findings.
  - [x] Automated Test Suite: **607 / 607 Automated Tests Passed (100%)** (530 Unit Tests + 77 Integration Tests) with 0 warnings (`-warnaserror`).
  - [x] Next.js Dashboard: Production build clean with 0 errors.

- [x] Step 9.2 — Durable Scheduler Hardening & PostgreSQL Concurrency Contract (FULLY IMPLEMENTED & VERIFIED):
  - [x] Atomic dispatch: `SecurityScanJob` INSERT + campaign cursor UPDATE + `CampaignExecutionAuditLog` INSERT commit in one `SaveChangesAsync`, with zero side effects from the losing instance.
  - [x] Canonical v1 occurrence key requires UTC and truncates sub-microsecond ticks to PostgreSQL precision, enforced by partial unique index `IX_security_scan_jobs_campaign_occurrence_key`.
  - [x] Claim loss requires exact SQLSTATE `23505`/constraint classification or a transient unknown-commit outcome **plus** the complete durable job/campaign/audit tuple. A job row alone is an integrity error.
  - [x] Failed writes are detached for wrapped EF failures and provider exceptions surfaced directly during commit; cancellation propagates instead of being counted as an error.
  - [x] `IDatabaseErrorClassifier` is a required dependency (both methods accept `Exception`), so a missing registration fails fast rather than silently disabling classification.
  - [x] `Repository`/`AnalysisJob` concurrency uses PostgreSQL-native `xmin`; legacy `bytea` tokens and bidirectional `security_scan_jobs` `Version`/`JobVersion` synchronization remain as tenant-schema-scoped bridges.
  - [x] Authoritative gate: **9/9** real-PostgreSQL `CampaignSchedulerRaceTests`, including a deterministic two-party barrier, pre/post-commit provider failures, and bidirectional counter fencing.

- [x] Step 9.3 — Operational Campaign Lifecycle & Observability (FULLY IMPLEMENTED & VERIFIED):
  - [x] Strict read boundary: `CampaignObservabilityService` observes Phase 9.2 state and contains zero dispatch, claim, retry, or mutation logic.
  - [x] Deterministic health precedence: `FailClosed` > `Unavailable` > `Degraded` > `NotConfigured` > `Healthy`.
  - [x] Endpoints on `/api/v1/security/campaigns`: `GET health`, `GET metrics` (`24h`/`7d`/`30d`), `GET {id}/history` (paginated, decision/since filters), `GET {id}/diagnostics`.
  - [x] Authenticated identity is authoritative for tenant resolution; `X-Tenant-ID` spoofing by non-admins is blocked.
  - [x] Diagnostics and recovery history are sourced from the immutable `CampaignExecutionAuditLog`; queries are index-bounded and pagination is capped.
  - [x] Dashboard: campaigns tab in `ScanManagementView` with health card, history drawer, and diagnostics modal on visibility-aware polling.

- [x] Step 9.4 — SPEC-008.5/008.6 Deployment Webhook & Orchestration Wiring (COMPLETED & VERIFIED):
  - [x] `DeploymentWebhookHandler` validates required headers, ±5-minute timestamp tolerance, duplicate webhook IDs, payload JSON, server-side target authorization, and constant-time HMAC-SHA256 signatures.
  - [x] Scan-job creation is delegated to a required `IDeploymentScanJobEnqueuer`. The handler no longer fabricates a job identifier, fails closed with `SCAN_JOB_ENQUEUE_FAILED`, and records webhook idempotency only after durable creation so a failed enqueue stays retryable.
  - [x] `RegisteredApplication` (tenant-scoped HMAC secret + authorized target URL) and `DeploymentWebhookRecord` (idempotency log) entities mapped and migrated (`20260920000001_AddDeploymentWebhookTables`).
  - [x] `DatabaseApplicationTargetResolver` implemented with ASP.NET Core Data Protection secret decryption and durable idempotency logging.
  - [x] `DatabaseDeploymentScanJobEnqueuer` implemented, persisting durable `SecurityScanJob` with `TriggeredBy="CiCdWebhook"`, `RequestedByUserId=null`.
  - [x] `InMemoryDeploymentLeaseStore` implemented providing thread-safe, tenant-isolated lease store for `DeploymentConcurrencyGate`.
  - [x] `DeploymentWebhookController` (`POST /api/v1/webhooks/deployments`) exposed with `[AllowAnonymous]`/`[IgnoreAntiforgeryToken]`, HMAC-only authentication, and mapped error codes (400/401/409/500).
  - [x] Registered all services in DI across both `Platform.Api` and `Platform.Worker`.
  - [x] Unit test suite covering `DatabaseDeploymentScanJobEnqueuer` and `InMemoryDeploymentLeaseStore` (16 tests, 100% pass).
  - [!] End-to-end deployment scan execution remains Docker-blocked because `IScannerRuntimeSandbox` resolves to `UnavailableScannerRuntime` (`SCANNER_RUNTIME_DISABLED`).










