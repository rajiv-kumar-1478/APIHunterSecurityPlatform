# SPEC-001 — APIHunter Security Intelligence Platform — Implementation Blueprint

This is the **master implementation blueprint** for the APIHunter Security Intelligence Platform. All agents and development work must align with the contracts and boundaries specified in this blueprint; no module should be redesigned independently.

The platform is built on **.NET 10 + EF Core 10**, leaving the existing APIHunter application untouched as an external integration source.

---

# 1. System Goal

Build a separate web-based security intelligence platform around the existing APIHunter system.

The platform provides:

* APIHunter dashboard
* APIHunter command/job management
* APIHunter discovery synchronization
* `Valid` / `ValidNoCredits` repository investigation
* Whole-repository AI analysis
* Verified credential intelligence
* Related API/cloud/database/server credential discovery
* Continuous website monitoring
* JavaScript/API/network intelligence
* BugHunter-AI integration through an adapter
* Optional Burp/MCP local agent
* Security findings and evidence
* Admin-controlled user permissions
* AI provider pool using **Admin-authorized** API keys
* AI-powered system health/debugging
* Email/Telegram notifications
* Durable jobs and worker recovery
* Horizontal worker scaling
* Complete audit trail

---

# 2. Non-Negotiable Architecture Rules

### Rule 1 — Never modify APIHunter directly for dashboard functionality
The existing APIHunter database is an external source accessed via read-only adapter.

```text
New Platform
     │
     ▼
APIHunter Adapter
     │
     ▼
Existing APIHunter DB
```

### Rule 2 — Platform has its own database
`APIHunter DB ≠ Platform DB`

Platform DB contains: users, permissions, imported APIHunter intelligence, repository investigations, credential candidates, validation results, websites, scans, findings, AI runs, workers, jobs, health, notifications, and audit logs.

### Rule 3 — External tools always use adapters
`IApiHunterSource`, `IAiProvider`, `ISecurityScanner`, `IBurpAgent`, `IObjectStorage`, `INotificationProvider`, `IRepositoryProvider`.
Never call third-party libraries directly from core domain or application business logic.

### Rule 4 — AI never becomes the source of truth
`AI hypothesis` ≠ `Credential candidate` ≠ `Credential validation` ≠ `Security finding` ≠ `Confirmed vulnerability`.
Do not collapse these distinct lifecycle concepts into one single status.

### Rule 5 — Worker count is irrelevant to correctness
The system must work correctly with 1 worker, 5 workers, or 50 workers without code changes.

### Rule 6 — No long-running state in worker RAM
Every long-running job must checkpoint progress to PostgreSQL/object storage. Worker restart must be recoverable.

### Rule 7 — Raw secrets are never returned by default
Raw credential values must be encrypted at rest and protected by explicit Admin-controlled permissions.

---

# 3. Recommended Technology Stack

| Layer            | Technology                                                               |
| ---------------- | ------------------------------------------------------------------------ |
| Backend          | ASP.NET Core 10                                                          |
| Runtime          | .NET 10 LTS                                                              |
| ORM              | EF Core 10                                                               |
| Database         | PostgreSQL                                                               |
| Queue            | PostgreSQL durable job queue initially                                   |
| Object storage   | S3-compatible abstraction → Cloudflare R2 initially                      |
| Frontend         | Next.js / React                                                          |
| API              | REST / OpenAPI                                                           |
| Authentication   | ASP.NET Core Identity + secure cookie/session or OIDC-ready architecture |
| Logging          | `ILogger` + OpenTelemetry                                                |
| Metrics          | OpenTelemetry                                                            |
| Tracing          | OpenTelemetry                                                            |
| AI               | Provider-independent AI Gateway                                          |
| Repository       | GitHub / API adapters                                                    |
| Website browser  | Playwright-based worker                                                  |
| Security scanner | BugHunter adapter                                                        |
| Burp             | Optional local agent                                                     |
| Email            | Provider adapter                                                         |
| Telegram         | Existing integration adapter                                             |

---

# 4. Repository Structure

```text
APIHunterSecurityPlatform/
│
├── src/
│   ├── Platform.Api/
│   ├── Platform.Application/
│   ├── Platform.Domain/
│   ├── Platform.Infrastructure/
│   ├── Platform.Worker/
│   ├── APIHunter.Adapter/
│   ├── AI.Gateway/
│   ├── Repository.Intelligence/
│   ├── SecurityCenter/
│   ├── BugHunter.Adapter/
│   ├── Burp.Agent/
│   └── Notifications/
├── frontend/
│   └── dashboard/
├── tests/
│   ├── Unit/
│   ├── Integration/
│   ├── Contract/
│   └── EndToEnd/
├── deployment/
├── docs/
└── README.md
```

---

# 5. Dependency Direction

```text
Domain
   ↑
Application
   ↑
Infrastructure
   ↑
API / Worker / Adapters
```

External adapters depend inward. Domain never depends on external libraries or frameworks.

---

# 6. Core Domain Model

## User
`Id`, `Email`, `Username`, `DisplayName`, `PasswordHash`, `IsAdmin`, `IsActive`, `CreatedAt`, `UpdatedAt`, `LastLoginAt`.
Roles: `ADMIN`, `USER`.

---

# 7. Permission Model

Permissions are code-based strings mapped to users via `UserPermission`.
Examples: `dashboard.view`, `apihunter.view`, `apihunter.search`, `apihunter.stop`, `repository.view`, `repository.investigate`, `credential.view`, `credential.view_validation`, `credential.view_ai`, `credential.reveal`, `credential.export`, `security.target.view`, `security.scan.view`, `security.scan.create`, `security.scan.stop`, `security.finding.view`, `security.finding.validate`, `ai.view`, `ai.manage`, `worker.view`, `worker.manage`, `system.health.view`, `notification.view`, `notification.manage`, `user.manage`, `permission.manage`, `audit.view`.

---

# 8. Field-Level Permissions

Controls visibility of sensitive resource fields:
`credential.raw_value`, `credential.validation_response`, `credential.code_context`, `finding.evidence`, `finding.network_data`, `repository.source`.

Evaluated at backend API layer.

---

# 9. Platform Database

Major tables: `users`, `permissions`, `user_permissions`, `field_permissions`, `api_hunter_sources`, `api_hunter_imports`, `repositories`, `repository_references`, `repository_snapshots`, `repository_investigations`, `credential_candidates`, `credentials`, `credential_validations`, `credential_assessments`, `credential_relationships`, `security_targets`, `web_assets`, `web_endpoints`, `network_observations`, `scan_schedules`, `scan_sessions`, `findings`, `finding_evidence`, `finding_validations`, `finding_history`, `jobs`, `job_attempts`, `job_checkpoints`, `workers`, `worker_capabilities`, `ai_providers`, `ai_provider_credentials`, `ai_models`, `ai_runs`, `ai_observations`, `ai_prompts`, `health_components`, `health_events`, `incidents`, `notification_rules`, `notification_deliveries`, `audit_events`.

---

# 10. APIHunter Adapter

Interface `IApiHunterSource`: schema mapping and synchronization abstraction for existing APIHunter database.

---

# 11. APIHunter Sync

Flow: APIHunter DB → Change detector → APIHunter adapter → Import queue → Platform DB.
Tracked in `api_hunter_imports` using source record hashing.

---

# 12. APIHunter Status Mapping

`IApiHunterStatusMapper` handles status translation (e.g. `Valid` → `VALID`, `ValidNoCredits` → `VALID_NO_CREDIT`).

---

# 13. Repository Investigation Trigger

Auto-queued investigation job when APIHunter imports a record with `Status = VALID` or `Status = VALID_NO_CREDIT` (controlled by admin toggle `Automatic AI Repository Investigation`).

---

# 14. Repository Deduplication

Multiple credentials pointing to the same repo share 1 repository entity, 1 snapshot, and 1 shared investigation index. Identity: `RepositoryId + CommitSha + AnalysisVersion`.

---

# 15. Repository Acquisition

Public repositories are fetched into snapshots and hashed to Object Storage. Private repositories without authorization trigger `ACCESS_REQUIRED`.

---

# 16. Repository Index

Build structured file tree, file classifications (`HIGH_VALUE`, `MEDIUM_VALUE`, etc.), IaC, CI/CD, and dependency indices before sending context to AI models.

---

# 17. Credential Detection

Candidate model `credential_candidates` records matches from pattern detectors, parsers, secret scanners, and AI suggestions.

---

# 18. Credential State Machine

`CANDIDATE` → `CONTEXT_ANALYSIS` → `VALIDATION_PENDING` → `VALIDATING` → (`VALID` | `VALID_NO_CREDIT` | `INVALID` | `UNKNOWN` | `UNSUPPORTED`).

---

# 19. Credential Validation

`ICredentialValidator` plugins perform non-destructive, safe validation against targets. Records `CredentialValidationResult`.

---

# 20. AI Repository Analysis

AI models receive structured JSON context and return strictly formatted JSON DTOs (`observations`, `relationships`, `risk`, `recommended_validations`, `summary`).

---

# 21. AI Security Investigation

Pipeline: Repository → Index → Deterministic Detection → Context Analysis → Validation → AI Relationship Analysis → Risk Scoring → Finding Generation.

---

# 22. AI Evidence Rule

Every AI observation requires file, line range, and commit SHA evidence references. No unsubstantiated severity claims allowed.

---

# 23. AI Provider Gateway

`IAiGateway` routes requests across authorized providers (`OpenAI`, `DeepSeek`, `Groq`, `Anthropic`). Only Admin-authorized keys in provider pool.

---

# 24. AI Provider Database

`ai_provider_credentials` tracks keys, priority, rate limits, daily/monthly quotas, health status, and fallback ordering.

---

# 25. AI Operations Copilot

Analyzes application/worker/adapter logs, metrics, health events, and stack traces to produce system diagnostic incidents and actionable recommendations.

---

# 26. Operations Observability

OpenTelemetry logs, metrics, and traces with standard correlation IDs across all components.

---

# 27. Health Checks

Standard ASP.NET Core health check endpoints returning `HEALTHY`, `DEGRADED`, `UNHEALTHY`, `OFFLINE`, `UNKNOWN` for DB, queue, storage, providers, and workers.

---

# 28. Durable Job System

PostgreSQL durable job queue with lease-locking (`FOR UPDATE SKIP LOCKED`) and `IJobQueue` interface abstraction.

---

# 29. Job Table

`jobs` table with statuses: `QUEUED`, `RUNNING`, `PAUSED`, `RETRYING`, `COMPLETED`, `FAILED`, `CANCELLED`.

---

# 30. Worker Claiming

PostgreSQL `FOR UPDATE SKIP LOCKED` row locking allows concurrent worker competition without race conditions.

---

# 31. Worker Heartbeat

Workers periodically send heartbeat updates to `workers` table.

---

# 32. Failed Worker Recovery

Jobs with expired worker leases (`LeaseExpiresAt < NOW()`) are automatically requeued for pick-up by healthy workers.

---

# 33. Checkpointing

Long-running jobs save incremental progress state in `job_checkpoints` to allow seamless resumption after worker restart.

---

# 34. Website Security Center

Target management via `security_targets` with authorized scan intervals and monitoring toggles.

---

# 35. Website Scan

Multi-stage pipeline: Passive discovery → JS analysis → Endpoint discovery → Network observation → AI analysis → Candidate finding → Validation.

---

# 36. JavaScript Intelligence

Downloads, hashes, diffs, and extracts API endpoints and configuration secrets from frontend JS bundles (`web_assets`, `web_endpoints`, `network_observations`).

---

# 37. BugHunter Adapter

`ISecurityScanner` interface decouples BugHunter scanner integration.

---

# 38. Burp Agent

Optional local outbound agent for Burp/MCP local integration without exposing local interfaces publicly.

---

# 39. Security Findings

Unified model (`findings`) supporting multiple sources (`APIHUNTER`, `REPOSITORY_AI`, `WEBSITE_SCANNER`, `BUGHUNTER`, `BURP`, `MANUAL`).

---

# 40. Finding Lifecycle

`DISCOVERED` → `INVESTIGATING` → `NEEDS_VALIDATION` → `CONFIRMED` (or `FALSE_POSITIVE` / `RESOLVED`). AI findings require validation evidence to reach `CONFIRMED`.

---

# 41. Evidence Storage

`finding_evidence` stores DB metadata and links to binary/large evidence artifacts stored in `IObjectStorage`.

---

# 42. Object Storage Interface

`IObjectStorage` abstraction backed initially by Cloudflare R2 (S3-compatible).

---

# 43. Notifications

`INotificationProvider` plugins (`EmailNotificationProvider`, `TelegramNotificationProvider`) managed via `notification_rules`. Secrets are masked in alerts.

---

# 44–49. Dashboard UX & Structure

Overview, APIHunter, Repository Intelligence, Security Center, Findings, AI, Workers, System Health, Notifications, Users, Permissions, Audit.

---

# 50–51. System Health & Operations AI

Health overview dashboard with Operations AI incident diagnosis for degraded components.

---

# 52–54. Security, Secret Encryption & Audit

HTTPS, secure cookies, CSRF, rate limiting, master-key secret encryption (`EncryptedSecret`), and comprehensive `audit_events` logging for all actions.

---

# 55–59. API Design & DTOs

Versioned `/api/v1/*` endpoints enforcing authentication, permissions, resource authorization, and field authorization DTO filtering.

---

# 60–65. Worker Handlers, Capabilities & Deployment

Handlers (`IJobHandler`) matched to worker capabilities across horizontal scaling tiers.

---

# 66. Migration Strategy

EF Core 10 migrations for all schema evolution.

---

# 67–75. Testing, Deduplication & Optimization

Unit, Integration, Contract, and E2E testing strategies; deduplication for repositories, files, and website scans.

---

# 76–83. Resilience, Admin Controls & Build Order

Failure scenarios (APIHunter DB offline, AI pool down, storage retry) handled gracefully. 11-phase modular build order.

---

# 84–90. Milestones & Definition of Done

Clear acceptance criteria from M1 (Platform boots) to M8 (Operations AI), with strict Definition of Done.

---

# 91. Most Important Architectural Invariants

```text
1. APIHunter DB is external and read-only.
2. Platform DB is independent.
3. APIHunter access goes through an adapter.
4. External security tools go through adapters.
5. AI provider output is never the sole source of truth; evidence and validation are required.
```
