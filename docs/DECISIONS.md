# Architecture Decision Log — APIHunter Security Intelligence Platform

---

## DEC-001: Separate Repository & Database for Platform
- **Date**: 2026-08-12
- **Title**: Physical Separation of Platform and APIHunterV2
- **Context**: The user requested a new web-based security intelligence platform while keeping the existing APIHunter application untouched.
- **Decision**: Create a brand new repository at `C:\Users\rk170\Desktop\APIHunterSecurityPlatform\` with its own PostgreSQL database. Do not modify or depend directly on `APIHunterV2` during Phase 1.
- **Alternatives**: Shared codebase or shared DB schema. Rejected to prevent breaking existing crawler logic.
- **Impact**: Platform remains cleanly isolated. APIHunterV2 will be connected in Phase 2 via read-only adapter contracts.

---

## DEC-002: Tech Stack Selection
- **Date**: 2026-08-12
- **Title**: .NET 10 + EF Core 10 + Next.js 15
- **Context**: Selecting LTS runtime and modern web frontend stack.
- **Decision**: Use .NET 10 Web API backend, EF Core 10 ORM, PostgreSQL database, and Next.js 15 (App Router) + Tailwind CSS frontend.
- **Impact**: Provides supported long-term foundation through 2028.

---

## DEC-003: Cookie Authentication + Anti-Forgery CSRF
- **Date**: 2026-08-12
- **Title**: Cookie-based Session Authentication with CSRF Tokens
- **Context**: Securing browser-to-backend communication for the management dashboard.
- **Decision**: Use HTTP-only SameSite cookies (`__ap_session`) backed by DB-persisted `AuthenticationSession` records, combined with ASP.NET Core `IAntiforgery` tokens sent via `X-CSRF-TOKEN` headers.
- **Impact**: Complete protection against CSRF and XSS token theft. Allows instant session revocation by admin or user.

---

## DEC-004: Password Hashing Standard
- **Date**: 2026-08-12
- **Title**: Use Microsoft.AspNetCore.Identity.PasswordHasher<TUser>
- **Context**: Avoiding custom password hashing implementations.
- **Decision**: Delegate all password hashing and verification to `IPasswordHasher<User>` (`PasswordHasher<User>`).
- **Impact**: Complies with PBKDF2/HMAC-SHA256 standards with work factors managed by .NET framework updates.

---

## DEC-005: Authorization & Field-Level Security Model
- **Date**: 2026-08-12
- **Title**: Platform Admin Bypass & Explicit ALLOW/DENY Field Permissions
- **Context**: Granular RBAC and field visibility control for sensitive security data.
- **Decision**: `IsPlatformAdmin = true` bypasses permission evaluations (audited). Non-admins evaluate explicit `Permission` records and `FieldPermission` rules with `ALLOW` or `DENY` effects. DTO projection occurs after authorization.
- **Impact**: Security boundaries enforced strictly on server side.

---

## DEC-006: Multi-Provider Notification Architecture
- **Date**: 2026-08-12
- **Title**: Adapter-Based Notification Infrastructure with Health Probes
- **Context**: Need flexible notification channels (SMTP, SendGrid, Mailgun) for alerts.
- **Decision**: Implement `INotificationProvider` adapters for MailKit SMTP, SendGrid SDK, and Mailgun API. All providers registered in DI. `ProviderSelector` routes traffic based on `EMAIL_PROVIDER` configuration.
- **Impact**: Zero code changes required to swap email delivery providers.

---

## DEC-007: Read-Only APIHunter Integration & Adapter Pattern
- **Date**: 2026-08-12
- **Title**: Decoupled Read-Only PostgreSQL Adapter & Normalized Synchronization
- **Context**: Need to import intelligence credentials from APIHunterV2 without modifying its database schema or executing write queries against its database.
- **Decision**: Define `IApiHunterSource` and `IApiHunterStatusMapper` contracts. Read-only PostgreSQL connection fetches APIKeys and RepoReferences incrementally. `ApiHunterSyncService` normalizes records, masks raw keys by default, encrypts raw keys at rest via Data Protection, deduplicates entity insertion by source ID, and audits reveal actions.
- **Impact**: APIHunterV2 database remains 100% read-only and decoupled from Platform business logic. Schema changes in APIHunterV2 can be handled inside `ApiHunterAdapter` without touching domain entities.

---

## DEC-008: Phase 3 Infrastructure Adapters & Security Package Verification
- **Date**: 2026-08-12
- **Title**: Package Verification, HMAC-SHA256 Fingerprinting, Context Redaction & FileSystem Dev Protection
- **Context**: Phase 3 Step 3 introduces Octokit GitHub API client, AWSSDK.S3 object storage, and deterministic secret detection.
- **Packages Verified**:
  - `Octokit` (v14.0.0, MIT License, .NET Standard 2.0 / .NET 10 compatible, zero vulnerabilities).
  - `AWSSDK.S3` (v4.0.102.1, Apache 2.0 License, .NET 10 compatible, zero vulnerabilities).
- **Decision**:
  - `IGitHubCredentialProvider` abstracts short-lived installation access tokens (`GitHubAppCredentialProvider`) and PAT fallback (`GitHubPatCredentialProvider`). Short-lived tokens are refreshed automatically and never logged/persisted.
  - `IObjectStore` uses `FileSystemObjectStore` in `Development` environment (guarded with an environment check that throws `InvalidOperationException` if executed in `Production`). `S3ObjectStoreAdapter` uses AWSSDK.S3 for production Cloudflare R2 / AWS S3 storage.
  - `RegexSecretDetector` consumes versioned `DetectionRule` entities dynamically (no hardcoded regexes in C#), applies `HMAC-SHA256(rawSecret, pepper_vX)` with key versioning, redacts context lines (`****REDACTED****`), and enforces resource bounds (5MB max file size, 100 max matches, 2s regex timeout).
  - Raw secret values are processed in transient memory only and never written to logs, telemetry, audit events, or unencrypted fields.
- **Impact**: Clean architecture compliance, secure credential handling, and zero raw secret exposure across logs/audits.

---

## DEC-009: Phase 3 Architecture Approval & Deterministic Detector Safety-Net Role
- **Date**: 2026-08-12
- **Title**: Unified Security Intelligence Platform Architecture & Role Partitioning
- **Context**: Final Phase 3 architectural lock-in for repository acquisition, index storage, seed ingestion, and secret candidate management.
- **Decision**:
  1. **Primary Seed Ingestion**: APIHunter repository references (`ApiHunterRepoReference`) are the primary discovery seeds. Repositories identified by APIHunter are eligible for acquisition and snapshot investigation even if deterministic detection yields 0 regex matches.
  2. **Detector Safety Net**: `RegexSecretDetector` is preserved as an independent deterministic safety net (secondary discovery layer). Detector matches represent candidate/evidence signals, not verified secrets.
  3. **Role Partitioning**:
     - **APIHunter**: Existing external intelligence & primary repository discovery seed.
     - **RegexSecretDetector**: Deterministic baseline safety net coverage.
     - **Phase 4 AI Investigation**: Deep contextual analysis & multiline secret relationship discovery.
     - **Phase 5 Validation**: Controlled credential verification against provider APIs.
- **Impact**: Decouples repository acquisition from regex discovery while maintaining structured evidence linkage across discovery sources.

---

## DEC-010: AI Provider Adapters, Model Availability & Raw Response Security
- **Date**: 2026-08-12
- **Title**: HttpClient Adapters for OpenAI, Anthropic, DeepSeek, and Groq with Strict Model Availability Fast-Failure & Raw Response Security
- **Context**: Phase 4 Step 3 requires implementing AI provider adapters for OpenAI, Anthropic, DeepSeek, and Groq without introducing bloated third-party SDKs or breaking .NET 10 compatibility.
- **Decision**:
  1. **Package Selection**: Use standard `System.Net.Http.HttpClient` and `System.Text.Json` rather than third-party provider SDK packages. Eliminates supply-chain vulnerabilities, guarantees 100% .NET 10 compatibility, and avoids heavy SDK dependencies.
  2. **API Key Security**: Provider API keys are decrypted in memory using `IDataProtector` ("Platform.AiProvider.ApiKey"). API keys are NEVER logged, returned in response DTOs, or exposed in exception messages.
  3. **Strict Model Availability (Zero Adapter Fallbacks)**: Adapters MUST NOT silently substitute fallback model strings if `AiProviderConfig.ModelName` is empty or unavailable. Unconfigured models return `InvalidModelConfiguration` (`IsRetryable = false`). HTTP 404 / `model_not_found` returns `ModelUnavailable` (`IsRetryable = false`). Model fallback is strictly delegated to Step 4 `AiModelRouter`.
  4. **Raw AI Response Security**: `AiPromptResponse.RawResponseContent` is treated as sensitive transient memory payload during normalization and schema validation. Raw responses are NEVER automatically written to `ILogger`, `AuditEvent` records, telemetry, or unencrypted database columns to prevent secret and code context leakage.
  5. **Error Classification & Response Normalization**: Adapters normalize response structures into `AiPromptResponse` and classify HTTP status codes into `Retryable` (`RateLimited`, `ProviderUnavailable`, `Timeout`) vs `NonRetryable` (`AuthenticationFailure`, `InvalidRequest`, `InvalidModelConfiguration`, `ModelUnavailable`).
- **Impact**: Zero external SDK bloat, strict raw API key protection, zero unhandled raw response leaks, and clean adapter isolation.

---

## DEC-011: AI Model Router Algorithm, Configurable Cooldown, Rate-Limit Separation & Health Recovery
- **Date**: 2026-08-12
- **Title**: Dynamic Database-Priority AI Router, Configurable Transient Cooldown, Rate-Limit Reset Separation, and Admin Health Recovery
- **Context**: Phase 4 Step 4 requires implementing dynamic provider routing, fallback cascades, configurable transient cooldown, capability matching, health recovery, and global administrative pause controls.
- **Decision**:
  1. **Dynamic Priority Selection**: Provider selection is driven by `AiProviderConfig.Priority` (descending order) loaded from the database — zero hardcoded fallback chains.
  2. **Configurable Transient Cooldown**: Bounded transient failure cooldown duration is configurable via `AiRouterOptions.TransientCooldownSeconds` (default: 120 seconds).
  3. **Rate-Limit Reset vs Generic Cooldown Distinction**:
     - `RateLimitResetAtUtc`: Set ONLY on genuine HTTP 429 rate-limit responses (`HealthStatus = RateLimited`).
     - `CooldownUntilUtc`: Set on generic transient failures such as timeouts, 503s, or network failures (`HealthStatus = Degraded`).
  4. **Non-Retryable Unreachable State**: Non-retryable errors (`AuthenticationFailure`, `InvalidModelConfiguration`, `InvalidRequest`) mark provider health as `Unreachable` without infinite retries.
  5. **Admin Health Recovery**: Updating a broken API key and running a successful test via `POST /api/v1/ai/providers/{id}/test` restores `HealthStatus = Healthy`, clears `LastErrorReason`, and resets cooldown timestamps, instantly re-enabling router eligibility. Transient cooldowns also restore eligibility automatically when `CooldownUntilUtc <= DateTime.UtcNow`.
  6. **Admin Global Pause Toggle**: Admin toggle `ai.global_enabled` (`SystemSetting`) instantly pauses all AI provider execution without purging or corrupting queued database jobs.
  7. **API Key Isolation**: Secret API keys are encrypted at rest with `IDataProtector` ("Platform.AiProvider.ApiKey"); DTOs, API endpoints, logs, and Next.js Admin UI expose only masked previews (`****1234`).
- **Impact**: Dynamic multi-provider resilience, automated transient failure recovery, strict key isolation, configurable cooldowns, and non-destructive Admin global control.

---

## DEC-012: Staged AI Repository Investigation Engine, Worker Lease Fencing & Discovery Provenance
- **Date**: 2026-08-12
- **Title**: Checkpointable Staged Pipeline, Atomic Worker Lease Fencing (`ClaimToken`), Complete Resource Limits Enforcement, and Provenance Preservation
- **Context**: Phase 4 Step 5 requires building a durable, multi-stage investigation engine that investigates repository snapshots safely with lease fencing and discovery source preservation.
- **Decision**:
  1. **Checkpointable Staged Pipeline**: Repository investigation progresses through 10 discrete stages (`AiInvestigationStageType`). Each completed stage persists an `AiInvestigationCheckpoint` containing `DurableResultJson`.
  2. **Atomic Worker Lease Fencing (`ClaimToken` Concurrency Token)**: `ClaimToken` is configured with `.IsConcurrencyToken()` in EF Core model configuration. Every SQL UPDATE statement generated by EF Core natively includes `WHERE id = @Id AND claim_token = @OriginalClaimToken`. When a worker calls `SaveWithLeaseCheckAsync(job, expectedClaimToken)`, EF Core sets `entry.Property(j => j.ClaimToken).OriginalValue = expectedClaimToken`. If Worker A's heartbeat stales and Worker B re-claims Job X (assigning a new `ClaimToken`), Worker A's mutation matches 0 rows and throws `DbUpdateConcurrencyException`, returning `false` without modifying any database records.

  3. **Preservation of Three Discovery Sources**:
     - `ApiHunterSync`: Primary discovery seed (APIHunter).
     - `DeterministicDetector`: Baseline safety net (RegexSecretDetector).
     - `AiInvestigator`: Contextual & relational discovery (Phase 4 AI Engine).
     - Provenance is explicitly tracked on every `AiInvestigationEvidence` record (`DiscoveryType`).
  4. **Strict Semantic Boundaries**: Regex matches, AI candidates, and unverified occurrences MUST NOT be automatically marked as `Valid` or `Validated` in Phase 4. Actual credential validity is strictly deferred to Phase 5.
  5. **Complete Runtime Resource Limits (`AiInvestigationEngineOptions`)**: Enforced at runtime:
     - `MaxFilesPerInvestigation` = 50 files
     - `MaxFileSizeBytes` = 1 MB
     - `MaxAiCallsPerInvestigation` = 20 calls
     - `MaxTokensPerInvestigation` = 100,000 tokens
     - `MaxStageRetries` = 3 retries per stage
     - `MaxInvestigationDurationMinutes` = 30 minutes
  6. **Idempotent Permanent Evidence Storage**: `AiInvestigationEvidence` records are persisted with a deterministic SHA-256 `Fingerprint` (`SnapshotId:EvidenceType:FilePath:StartLine:EndLine`). Re-running investigations avoids duplicate evidence creation.
  7. **Raw Secret Protection**: Prompts sent to AI adapters contain masked values (`****1234`), metadata, and structural context — raw secrets are NEVER transmitted to AI.
- **Impact**: Multi-worker fencing protection, bounded token/memory consumption, worker crash resilience, idempotent evidence persistence, and strict raw secret protection.

---

## DEC-013: Security Intelligence Graph & Edge Builder Architecture
- **Date**: 2026-08-12
- **Title**: Deterministic Graph Node/Edge Identity, Multi-Source Provenance Enrichment, Safe Normalization, and Historical Observation Tracking
- **Context**: Phase 4 Step 6 requires building a durable evidence-backed security intelligence graph connecting repositories, credentials, services, databases, domains, and environments without converting AI guesses into unverified truth.
- **Decision**:
  1. **Deterministic Node & Edge Identity**: Nodes are uniquely indexed on `(NodeType, Name)` (e.g. `repo:{id}`, `candidate:{id}`, `domain:{normDomain}`, `db:{normHost}`). Edges are uniquely indexed on `(SourceNodeId, TargetNodeId, EdgeType)`. Duplicate node or edge creation is strictly prevented by DB unique constraints and builder upserts.
  2. **Safe Entity Normalization**: Domains are stripped of schemes, paths, and ports (`https://EXAMPLE.COM/api` $\rightarrow$ `example.com`). Service names convert to lower-kebab (`web_api` $\rightarrow$ `web-api`). Environments normalize `prod`/`live` $\rightarrow$ `production`. Raw secrets are NEVER used as node identity or stored in display labels.
  3. **Multi-Source Provenance Preservation**: Every edge preserves `DiscoverySource` (`ApiHunterSync`, `DeterministicDetector`, `AiInvestigator`). When multiple discovery layers confirm the same relationship, existing edges are enriched (`LastObservedAtUtc` updated, confidence upgraded if higher, evidence references appended) rather than duplicated.
  4. **Historical Snapshot Tracking**: Nodes and edges record `FirstObservedAtUtc` and `LastObservedAtUtc`, preserving historical security relationships even if a commit snapshot resolves the file reference later.
  5. **Strict Semantic Boundaries**: Graph relationships represent evidence-backed associations, NOT confirmed vulnerabilities or validated credentials (validation remains Phase 5).
- **Impact**: Structured relational intelligence visualization, multi-source evidence traceability, zero duplicate edges, safe entity normalization, and historical security relationship tracking.

---

## DEC-014: Phase 5 Credential Validation Engine Architecture Plan
- **Date**: 2026-08-12
- **Title**: CandidateStatus Protection, Durable Job Reuse, DNS-Rebinding SSRF Protection, Fixed Provider Endpoints, Signed-Protocol Validators, and Evidence-Backed Classification
- **Context**: Phase 5 requires designing a secure credential validation framework without compromising candidate discovery statuses, introducing second job queues, or exposing internal networks.
- **Decision**:
  1. **Separation of Discovery vs Validation Truth**: `CredentialCandidate.Status` is strictly preserved for discovery/triage (`Detected`, `Triaged`, `Resolved`). Validation status is stored separately on `CredentialValidationResult.Status`.
  2. **Reuse of Existing Job Infrastructure**: Validation tasks reuse the existing durable `AnalysisJob` table (`JobType = CredentialValidation`) with `FOR UPDATE SKIP LOCKED` and `.IsConcurrencyToken()` ClaimToken fencing.
  3. **Strict SSRF & Fixed Provider Endpoints**: Target validation endpoints are hardcoded per provider (`AllowedEndpoints`). Candidates cannot supply target URLs. Resolves hostnames and validates ALL IPv4 & IPv6 addresses against private/loopback/cloud-metadata blocklists prior to HTTP dispatch with `AllowAutoRedirect = false`.
  4. **Provider-Specific Response Classifiers**: `HTTP 200` does not universally mean `Valid`. Responses must confirm authenticated identity. `HTTP 403` maps to `ValidInsufficientScope`, `Revoked`, or `BlockedByPolicy` (not blindly `Invalid`). `HTTP 429` maps to `RateLimited` with provider cooldown retry.
  5. **Signed-Protocol AWS Validator**: Uses `AwsStsCredentialValidator` calling STS `GetCallerIdentity` without exposing or logging AWS secret keys or session tokens.
  6. **Historical Revalidation & Confidence**: Validation results are appended historical records. Stores `ValidationConfidence`, `ValidatorVersion`, and `PolicyVersion`.
  7. **Narrow Decrypted Secret Scope**: Secrets are decrypted from AES-GCM storage in memory ONLY during validator execution and discarded immediately. ZERO secrets written to logs, DTOs, or database result fields.
- **Impact**: Secure, non-destructive credential validation, complete SSRF protection, historical validation traceability, and zero secret leakage.

---

## DEC-015: DNS-Rebinding Prevention via SocketsHttpHandler.ConnectCallback IP Pinning
- **Date**: 2026-08-12
- **Title**: Socket-Level Connection Binding to Validated IP Endpoint for DNS-Rebinding TOCTOU Prevention
- **Context**: Performing a separate DNS resolution prior to HTTP client dispatch allows a second uncontrolled DNS lookup by the operating system, creating a Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding vulnerability where a malicious DNS server could return a public IP during pre-check and a private/metadata IP (`169.254.169.254`, `127.0.0.1`) during HTTP connection.
- **Decision**:
  1. **Socket-Level ConnectCallback Binding**: Validation HTTP clients configure `SocketsHttpHandler.ConnectCallback`. The callback resolves hostnames, validates ALL returned A & AAAA IP addresses against blocklists, and opens the TCP `Socket` directly to `IPEndPoint(validatedIp, port)`.
  2. **Preservation of TLS SNI & Hostname Identity**: The underlying `SslStream` receives the original allowlisted provider hostname (`api.openai.com`), preserving TLS Server Name Indication (SNI) and certificate validation while eliminating secondary DNS lookups.
  3. **Zero Secondary DNS Resolution**: By supplying a connected `NetworkStream` directly to `SocketsHttpHandler`, the HTTP client is physically incapable of performing an independent second DNS lookup.
- **Impact**: Absolute protection against DNS rebinding, TOCTOU SSRF exploits, and IP blocklist bypasses while maintaining 100% TLS certificate validation integrity.

---

## DEC-016: Reuse of ASP.NET Core DataProtection Provider for Credential Decryption
- **Date**: 2026-08-12
- **Title**: Unified DataProtection Purpose String `Platform.SecretCandidate.RawValue` for Decryption
- **Context**: `CredentialCandidate.EncryptedRawValue` was encrypted during secret detection (Phase 3) using ASP.NET Core Data Protection with purpose `"Platform.SecretCandidate.RawValue"`.
- **Decision**:
  1. **Consistent DataProtection Provider**: Validation services (`CredentialValidationService`, `CredentialValidationWorker`) inject `IDataProtectionProvider` and create protector `IDataProtector _rawProtector = dataProtectionProvider.CreateProtector("Platform.SecretCandidate.RawValue")`.
  2. **In-Memory Decryption Isolation**: Secret strings are decrypted strictly inside transient validator execution scopes using `_rawProtector.Unprotect(candidate.EncryptedRawValue)` and discarded immediately after HTTP request processing.
  3. **Zero Encryption Scheme Fragmentation**: Avoids creating a second ad-hoc encryption scheme (such as custom AES-GCM keys) for validation, preserving unified cryptographic lifecycle management across the platform.
- **Impact**: Consistent security architecture, zero secret leakage, and seamless integration with existing candidate storage.

---

## DEC-017: Security Intelligence Graph Integration & Validation Provenance Coexistence
- **Date**: 2026-08-12
- **Title**: Dynamic Validation Enrichment and Cross-Source Provenance Preservation in Intelligence Graph
- **Context**: Phase 5 validation results must enrich the Security Intelligence Graph without overwriting original discovery provenance (`ApiHunterSync`, `DeterministicDetector`, `AiInvestigator`) or mutating `CredentialCandidate.Status`.
- **Decision**:
  1. **Cross-Source Provenance Coexistence**: Added `CredentialValidation` to `DiscoveryType` enum. Graph edges carry validation evidence references without mutating discovery sources.
  2. **Node Identity Deduplication & Dynamic Metadata**: Graph node creation/updates (`SecurityIntelligenceGraphBuilder.cs`) update existing `CredentialCandidate` node labels (`[Valid]`, `[Invalid]`) and metadata (`isCurrentlyValidated`, `latestValidationStatus`) dynamically upon re-validation rather than creating duplicate graph entities.
  3. **Re-Validation State Transition**: When re-validation marks a credential as `Invalid`, `Expired`, or `Revoked`, `isCurrentlyValidated` updates to `false`, ensuring invalid credentials are no longer represented as currently validated.
  4. **Strict Discovery Lifecycle Separation**: `CredentialCandidate.Status` discovery/triage state (`Detected`, `Triaged`, `Resolved`) remains 100% untouched by validation truth.
- **Impact**: Provides full historical transparency, dynamic graph state updates, and immutable discovery provenance tracking across all credential nodes.

---

## DEC-018: Finding Lifecycle Governance Contract Option A & Optimistic Concurrency
- **Date**: 2026-08-12
- **Title**: Option A Resolution Fields Gating & LifecycleVersion Optimistic Concurrency
- **Context**: Phase 6 Step 5 established finding lifecycle governance. Required clarifying when resolution fields are populated and preventing lost updates.
- **Decision**:
  1. **Option A Resolution Contract**: `ResolvedAtUtc`, `ResolvedByUserId`, and `ResolutionReason` are populated **strictly when `FindingStatus.Resolved`**. For `Remediated`, `AcceptedRisk`, and `FalsePositive`, resolution fields remain null. Re-opening a finding resets resolution fields to null.
  2. **Mandatory Reason Requirement**: All status transitions require a non-empty `Reason` string recorded in the append-only `SecurityFindingStatusHistory` audit table. `ResolutionReason` is required for `Resolved` transitions.
  3. **Optimistic Concurrency Guard**: `SecurityFinding.LifecycleVersion` configured with `IsConcurrencyToken()`. All transition requests pass `ExpectedLifecycleVersion`; version mismatch returns `409 Conflict`.
  4. **Purity Preservations**: `RiskEngine.cs` and `CredentialCandidate.Status` remain completely isolated and untouched by governance transitions.
- **Impact**: Clean, predictable finding lifecycle model, complete audit trail, and zero concurrency conflicts.

---

## DEC-019: Continuous Revalidation, Secret-Safe Alerting & Security Center Read-Only Architecture
- **Date**: 2026-08-12
- **Title**: Continuous Revalidation Transient Exclusion, Database-Backed Atomic Alert Leases, and Read-Only Security Center Posture
- **Context**: Integrating continuous revalidation (Step 6), high-fidelity alerting (Step 7), and dashboard UI (Step 8) into the platform.
- **Decision**:
  1. **Continuous Revalidation Scheduling**: `ContinuousRevalidationWorker` uses two-timeline scheduling: a candidate is due when definitive validation age $> \text{MinRevalidationIntervalHours}$. Recent transient failures (`RateLimited`, `Unavailable`) do NOT postpone overdue revalidations.
  2. **Transient Failure Exclusion**: `ValidationStateChangeProcessor` skips processed timestamp updates and graph status changes on transient failures (`RateLimited`, `Unavailable`), ensuring transient outages do not clear validation truth or trigger false alerts.
  3. **Database-Backed Atomic Alert Leases**: `SecurityAlertService` uses database-backed atomic claim leases (`SecurityAlertLog`) keyed by canonical fingerprint (`finding:` or `repository:`). Prevents duplicate notification dispatch across concurrent workers while enforcing a 60-minute cooldown window.
  4. **Fail-Closed Alert Configuration**: `SecurityAlertOptions.GlobalEnabled` defaults to `false`. Notifications strictly render `MaskedValue` (`sk-proj-****1234`); raw secrets are never accessed or sent.
  5. **Read-Only Security Center Architecture**: `SecurityCenterController.GetSecurityPosture()` reads persisted `RepositoryRiskScore` DB rows calculated by Step 2/6/7. **It does NOT invoke RiskEngine.Calculate()**. Next.js frontend performs **0 client-side risk math** and displays backend DTOs only. `GET /alerting-status` returns a sanitized DTO without secrets.
- **Impact**: Reliable continuous revalidation, zero duplicate alerts, complete secret protection, and strict risk engine architectural isolation.















