# Master Execution Task Plan: Phase 10 & Phase 11

**Platform:** APIHunter Security Platform  
**Target Phases:** Phase 10 (Operations AI) & Phase 11 (Production Hardening)  
**Status:** Completed & Fully Verified  
**Specification References:** [SPEC-001_MASTER_BLUEPRINT.md](file:///c:/Users/rk170/Desktop/APIHunterSecurityPlatform/docs/SPEC-001_MASTER_BLUEPRINT.md), [MASTER_BLUEPRINT.md](file:///c:/Users/rk170/Desktop/APIHunterSecurityPlatform/docs/MASTER_BLUEPRINT.md), [SPEC-008_SCANNER_CAPABILITY_EXPANSION_CONTRACT.md](file:///c:/Users/rk170/Desktop/APIHunterSecurityPlatform/docs/SPEC-008_SCANNER_CAPABILITY_EXPANSION_CONTRACT.md)

---

## Table of Contents
1. [Overview & Architectural Context](#1-overview--architectural-context)
2. [Phase 10: Operations AI](#2-phase-10-operations-ai)
   - [10.1 Structured Telemetry, Metrics & Distributed Tracing](#101-structured-telemetry-metrics--distributed-tracing)
   - [10.2 Autonomous Incident Engine & Deadlock Recovery](#102-autonomous-incident-engine--deadlock-recovery)
   - [10.3 AI Operational Diagnosis Engine](#103-ai-operational-diagnosis-engine)
   - [10.4 Operations & Incident Triage Dashboard UI](#104-operations--incident-triage-dashboard-ui)
   - [10.5 Phase 10 Comprehensive Test Suite](#105-phase-10-comprehensive-test-suite)
3. [Phase 11: Production Hardening](#3-phase-11-production-hardening)
   - [11.1 Tiered Rate Limiting & Abuse Prevention](#111-tiered-rate-limiting--abuse-prevention)
   - [11.2 Automated Backup, PITR & Disaster Recovery (DR) Protocols](#112-automated-backup-pitr--disaster-recovery-dr-protocols)
   - [11.3 High-Concurrency Stress, Benchmarking & DB Optimization](#113-high-concurrency-stress-benchmarking--db-optimization)
   - [11.4 Scanner Sandbox Hardening & Adapter Contract Test Harness](#114-scanner-sandbox-hardening--adapter-contract-test-harness)
   - [11.5 Final Production Readiness, Security Gates & Live Deployment](#115-final-production-readiness-security-gates--live-deployment)
   - [11.6 Phase 11 Comprehensive Test Suite](#116-phase-11-comprehensive-test-suite)
4. [Step-by-Step Implementation Sequence](#4-step-by-step-implementation-sequence)
5. [Definition of Done (DoD) Checklist](#5-definition-of-done-dod-checklist)

---

## 1. Overview & Architectural Context

With **Phases 1 through 9.4 100% complete and verified** (including 34-provider credential validation parity, continuous scan campaigns, and CI/CD deployment verification webhooks), the platform now requires production-grade operational resilience and enterprise hardening.

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                       CURRENT STATE: PHASES 1 - 9.4                         │
│  ✓ Core DB, Auth & RBAC          ✓ Secret Encryption (AES-GCM / DPAPI)        │
│  ✓ PostgreSQL SKIP LOCKED Queue  ✓ Static & AI Candidate Detection           │
│  ✓ 34-Provider Validation Parity ✓ Continuous Scan Campaigns (9.1-9.3)       │
│  ✓ Unified Finding Lifecycle     ✓ CI/CD Deployment Webhooks (9.4)           │
│  ✓ Automated Remediation Engine  ✓ Scanner Capability Contract (SPEC-008)    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         PHASE 10: OPERATIONS AI                              │
│  • Distributed Tracing & Telemetry (OpenTelemetry, Prometheus metrics)       │
│  • Autonomous Incident Engine (Worker stalls, lease recovery, alerts)        │
│  • AI Operational Diagnosis (Sanitized root-cause analysis via AI Router)    │
│  • Real-Time Operations UI (/operations: Health, Incidents, Diagnostics)     │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                      PHASE 11: PRODUCTION HARDENING                          │
│  • Multi-Tier Rate Limiting (Partitioned IP/Tenant, 429 Retry-After)         │
│  • Automated Backup & Point-in-Time Recovery (PITR) Drills                   │
│  • High-Concurrency Stress Testing (1,000 concurrent jobs benchmark)        │
│  • Docker Scanner Sandbox Hardening (cgroups, non-root, seccomp, drop-caps)  │
│  • Final Security Audit & Production Release Gate                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Phase 10: Operations AI

Phase 10 provides intelligent observability, autonomous failure detection, and LLM-assisted root-cause diagnosis for the platform's distributed architecture (API, background workers, and PostgreSQL queue).

### 10.1 Structured Telemetry, Metrics & Distributed Tracing
- **Objectives:** Implement OpenTelemetry-compliant tracing and Prometheus metrics across all backend processes without leaking credentials.
- **Key Deliverables:**
  1. `PlatformMetrics`:
     - Counters: `security_jobs_dispatched_total`, `security_jobs_completed_total`, `security_jobs_failed_total`, `security_jobs_timed_out_total`.
     - Gauges: `worker_active_count`, `queue_pending_depth`, `campaign_overdue_count`, `active_incident_count`.
     - Histograms: `job_execution_duration_seconds` (buckets: 0.1s to 600s), `ai_validation_duration_seconds`, `db_query_duration_seconds`.
  2. `ActivitySource` Tracing:
     - Trace correlation IDs propagated from HTTP incoming requests (`traceparent` header) $\rightarrow$ `SecurityScanJob.CorrelationId` $\rightarrow$ Worker execution $\rightarrow$ Database queries $\rightarrow$ AI Gateway requests.
  3. Sanitized Logging Enrichment:
     - Structured JSON logs with `TenantId`, `JobId`, `CorrelationId`, `WorkerId`.
     - Masking filter: Automatically redacts patterns matching API keys, bearer tokens, passwords, and private keys.

### 10.2 Autonomous Incident Engine & Deadlock Recovery
- **Objectives:** Continuously inspect system state, automatically categorize failures into formal incidents, trigger self-healing recovery, and notify operators.
- **Domain Model:**
  - `OperationalIncident`:
    - `Id` (Guid, PK)
    - `TenantId` (Guid?, nullable for platform-wide incidents)
    - `Severity` (`Critical`, `High`, `Medium`, `Low`, `Info`)
    - `Category` (`WorkerHeartbeatLost`, `LeaseDeadlock`, `DatabaseDegraded`, `CampaignStall`, `AiProviderQuotaExhausted`, `ConsecutiveJobFailures`)
    - `Status` (`Detected`, `Investigating`, `Mitigated`, `Resolved`, `Suppressed`)
    - `Title` (string)
    - `Fingerprint` (string, for deduplication/grouping)
    - `FirstObservedAtUtc` (DateTime)
    - `LastObservedAtUtc` (DateTime)
    - `ResolutionNotes` (string?)
    - `MitigationActionTaken` (string?)
    - `AiDiagnosisId` (Guid?, FK to `AiOperationalDiagnosis`)
- **Detection & Self-Healing Logic (`IncidentEngineWorker` / `IncidentOrchestrationService`):**
  - **Worker Heartbeat Loss:** If a worker's heartbeat expires ($> 3\times$ interval) while holding active job leases:
    1. Mark worker as `Dead`.
    2. Revoke and release expired job leases back to `Pending` (incrementing retry count).
    3. Generate/update `OperationalIncident` with severity `High`.
  - **Campaign Stall Detection:** If an active campaign's `NextRunUtc` is overdue by $> 15$ minutes and no job is active:
    1. Force claim reset and reschedule occurrence.
    2. Generate `OperationalIncident` with severity `Medium`.
  - **DB Degradation:** Detect query timeout surges or deadlocks $\rightarrow$ Trigger graceful worker backoff (exponential polling delay).
  - **De-duplication:** Incidents with matching `Fingerprint` within a 1-hour window update `LastObservedAtUtc` and event counter instead of creating duplicates.

### 10.3 AI Operational Diagnosis Engine
- **Objectives:** Provide instant, automated root-cause analysis for failed scan campaigns, worker timeouts, and validation errors using the existing AI Gateway (`IAiGateway`), strictly sanitized against token leaks.
- **Domain Model:**
  - `AiOperationalDiagnosis`:
    - `Id` (Guid, PK)
    - `IncidentId` (Guid, FK to `OperationalIncident`)
    - `AnalyzedAtUtc` (DateTime)
    - `ProviderUsed` (string, e.g. "openai", "deepseek", "azure-openai")
    - `RootCauseSummary` (string)
    - `SuggestedRemediation` (string)
    - `ConfidenceScore` (double, 0.0 - 1.0)
    - `IsDeterministicClassification` (bool)
    - `RawSanitizedPrompt` (string, for auditing)
- **Sanitization & Prompt Engineering:**
  - Strict Sanitizer (`IOperationalPromptSanitizer`):
    - Strips all raw token strings, Authorization headers, regex patterns matching known provider tokens.
    - Anonymizes repository URLs and internal server IPs.
  - Prompt Template:
    - Provides error stack traces, execution duration, worker metadata, and system resource counters.
    - Requests structured JSON schema output: `{ "rootCause": "...", "remediation": "...", "confidence": 0.95, "category": "..." }`.
  - Fail-Safe: If AI Gateway is unavailable or throttled, falls back to deterministic rule-based diagnosis (`DeterministicDiagnosisFallback`).

### 10.4 Operations & Incident Triage Dashboard UI
- **Route:** `/operations` (Admin / Operator role protected).
- **Components:**
  1. **System Health & Worker Fleet Matrix:**
     - Live cards showing Active Workers, Queue Depth, Processing Latency (P50/P95/P99), DB Connection Pool saturation.
     - Worker list with hostname, version, last heartbeat, active lease count, and status badge (Green/Amber/Red).
  2. **Active Incidents Table:**
     - Filterable by Severity, Status, Category, and Tenant.
     - Color-coded severity chips (`Critical` in pulsing red, `High` in orange, etc.).
     - Quick actions: "Acknowledge", "Trigger Self-Healing", "View AI Diagnosis", "Resolve".
  3. **AI Diagnostic Drawer / Modal:**
     - Displays AI-generated root cause, confidence bar, and step-by-step mitigation recommendations.
     - One-click "Execute Automated Mitigation" button where applicable (e.g., reset lease, restart campaign).
  4. **Live Telemetry Stream:**
     - Auto-refreshing event log of recovery actions and worker heartbeats with pause/resume toggle.

---

### 10.5 Phase 10 Comprehensive Test Suite

#### 10.5.1 Unit Tests (`APIHunter.Tests.Unit.Operations`)
| Test ID | Test Target | Scenario & Expected Behavior |
|---|---|---|
| `UT-10-01` | `IncidentEngineService` | Detects expired worker heartbeat ($> 90$s) and generates single `WorkerHeartbeatLost` incident. |
| `UT-10-02` | `IncidentEngineService` | Duplicate incident fingerprints within 60 minutes aggregate into existing incident, incrementing counter. |
| `UT-10-03` | `OperationalPromptSanitizer` | Strips AWS secrets (`AKIA...`), GitHub tokens (`ghp_...`), and Bearer headers from stack traces before AI prompt build. |
| `UT-10-04` | `AiOperationalDiagnosisService` | Validates structured JSON parsing from `IAiGateway` response and records diagnosis against incident. |
| `UT-10-05` | `DeterministicDiagnosisFallback` | When `IAiGateway` throws timeout/circuit-breaker, produces valid fallback diagnosis with 1.0 confidence on known error codes. |
| `UT-10-06` | `PlatformMetricsCollector` | Verifies Prometheus metrics increment correctly on job dispatch, completion, and failure events. |
| `UT-10-07` | `ActivityTracingMiddleware` | Confirms W3C `traceparent` header extraction and correlation ID injection into ambient execution context. |

#### 10.5.2 Integration Tests (`APIHunter.Tests.Integration.Operations`)
| Test ID | Test Target | Scenario & Expected Behavior |
|---|---|---|
| `IT-10-01` | `PostgreSqlIncidentRepositoryTests` | Verifies atomic upsert of incidents and foreign key cascades to `AiOperationalDiagnosis`. |
| `IT-10-02` | `WorkerCrashRecoveryIntegrationTests` | Simulates a crashed worker holding 5 job leases; `IncidentEngineWorker` releases all leases to `Pending` and logs audit records within 1 cycle. |
| `IT-10-03` | `CampaignStallSelfHealingTests` | Overdue campaign with stuck queue lock is automatically unfrozen and scheduled to next future interval. |
| `IT-10-04` | `OperationsApiControllerTests` | `GET /api/v1/operations/incidents` validates RBAC (Admin only) and returns correct pagination/filtering. |
| `IT-10-05` | `AiDiagnosisEndToEndMockTests` | End-to-end flow: Job fails $\rightarrow$ Incident created $\rightarrow$ AI Diagnosis requested $\rightarrow$ Diagnosis stored and linked. |

#### 10.5.3 Frontend Verification Tests (`frontend/dashboard`)
| Test ID | Component / Page | Verification Criteria |
|---|---|---|
| `FE-10-01` | `/operations/page.tsx` | Next.js prerender and client hydration with mock incident and telemetry data. |
| `FE-10-02` | `IncidentList.tsx` | Correct severity badge color rendering, sorting by `LastObservedAtUtc`, and pagination. |
| `FE-10-03` | `AiDiagnosisModal.tsx` | Displays formatted markdown root cause, confidence score bar, and copy-to-clipboard button. |
| `FE-10-04` | `WorkerFleetStatus.tsx` | Shows worker heartbeat freshness; highlights stale/dead workers in red. |

---

## 3. Phase 11: Production Hardening

Phase 11 implements enterprise-grade resilience, multi-tenant rate limiting, disaster recovery procedures, high-concurrency performance verification, and container sandbox hardening.

### 11.1 Tiered Rate Limiting & Abuse Prevention
- **Objectives:** Protect API endpoints from DDoS, credential stuffing, and abusive continuous scan triggers using ASP.NET Core native partitioned rate limiting (`Microsoft.AspNetCore.RateLimiting`).
- **Policy Configuration:**
  1. **Global Anonymous IP Policy:**
     - Sliding window: 100 requests per minute per client IP.
  2. **Authentication / Login Policy:**
     - Fixed window: 5 requests per 15 seconds per IP/User to prevent brute-force attacks.
  3. **Authenticated Tenant API Policy:**
     - Partitioned by `TenantId`: Token bucket (Capacity: 300, Refill: 50/sec) with burst tolerance.
  4. **CI/CD Webhook Ingestion Policy (`/api/v1/webhooks/deployments`):**
     - Partitioned by `ApplicationId`: Concurrency limiter (Max 10 concurrent requests) + 60 requests per minute.
  5. **Standardized 429 Response Handling:**
     - Returns RFC-7807 `ProblemDetails` with `Retry-After` header and `X-RateLimit-Reset`.

### 11.2 Automated Backup, PITR & Disaster Recovery (DR) Protocols
- **Objectives:** Establish deterministic database backup automation, Point-in-Time Recovery (PITR), and cryptographic key backup protocols.
- **Key Deliverables:**
  1. Automated PostgreSQL Backup Scripts (`deployment/backup/`):
     - `backup_full.sh` / `backup_full.ps1`: Nightly compressed `pg_dump` with SHA-256 verification and encryption.
     - `backup_wal.sh`: Continuous Write-Ahead Log (WAL) archiving for PITR recovery.
     - Retention policy: 7 daily, 4 weekly, 12 monthly backups with automatic pruning.
  2. Data Protection Key Rotation & Backup:
     - Documented protocol for ASP.NET Core Data Protection certificate/key ring persistence and disaster restoration.
  3. Disaster Recovery Drill Script & Guide (`docs/operations/DISASTER_RECOVERY_RUNBOOK.md`):
     - Step-by-step restoration from scratch into a fresh PostgreSQL instance, verifying schema migrations, tenant data integrity, and encrypted credential decryption.

### 11.3 High-Concurrency Stress, Benchmarking & DB Optimization
- **Objectives:** Verify the PostgreSQL queue and dispatch engine under high load (1,000 concurrent jobs) without deadlocks or connection exhaustion.
- **Key Deliverables:**
  1. Concurrency Benchmark Suite (`tests/APIHunter.Tests.Load`):
     - Simulates 50 concurrent tenant campaigns dispatching 1,000 scan jobs simultaneously across 8 simulated worker nodes.
  2. Database Optimization & Connection Pooling:
     - Connection pool configuration: Minimum pool size, maximum pool size, connection lifetime, and command timeouts.
     - Index Verification: Run `EXPLAIN ANALYZE` on queue query (`FOR UPDATE SKIP LOCKED`) to ensure index-only scans on `(status, scheduled_at_utc)`.
     - Deadlock prevention validation: Guarantee all multi-table transactions acquire locks in identical deterministic order.

### 11.4 Scanner Sandbox Hardening & Adapter Contract Test Harness
- **Objectives:** Ensure any scanner tool executed in hosted environments is completely isolated and cannot escape or escalate privileges.
- **Key Deliverables:**
  1. Linux / Docker Sandbox Profile (`deployment/docker/sandbox.seccomp.json`):
     - Read-only root filesystem (`--read-only`).
     - Dropped capabilities (`--cap-drop=ALL`).
     - Non-root user execution (`--user 10001:10001`).
     - No-new-privileges flag (`--security-opt=no-new-privileges:true`).
     - Memory limits (`--memory=2g`), CPU limits (`--cpus=2.0`), and PID limits (`--pids-limit=256`).
     - Egress proxy requirement (`ALL_PROXY` pinned to Egress Gateway; direct outbound blocked).
  2. Pluggable Adapter Contract Test Harness:
     - Reusable test suite (`ScannerAdapterContractTests<TAdapter>`) verifying:
       - Strict timeout termination.
       - Clean temp file deletion on cancellation or failure.
       - Fail-closed error handling when binary is corrupted or missing.
       - Output JSON schema validation against `NormalizedScanResult`.

### 11.5 Final Production Readiness, Security Gates & Live Deployment
- **Objectives:** Execute final security audit checks, environment variable validation, and production container packaging.
- **Key Deliverables:**
  1. Startup Environment Validator (`EnvironmentValidationHostedService`):
     - Validates at application startup: Database connectivity, Master encryption key length ($\ge 256$-bit), JWT signing key entropy, HTTPS enforcement, CORS origin restrictions.
     - Fail-closed behavior: If any production secret is default/insecure, platform refuses to start.
  2. Health & Readiness Probes:
     - `/health/live` (Liveness): Returns 200 if process is responsive.
     - `/health/ready` (Readiness): Returns 200 only if PostgreSQL and Master Key Provider are verified.
  3. Final Security Hardening Checklist:
     - Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), X-Content-Type-Options, Anti-clickjacking headers.

---

### 11.6 Phase 11 Comprehensive Test Suite

#### 11.6.1 Rate Limiting & Security Tests (`APIHunter.Tests.Unit.Hardening`)
| Test ID | Test Target | Scenario & Expected Behavior |
|---|---|---|
| `UT-11-01` | `RateLimitingMiddleware` | 6th rapid login attempt from same IP receives HTTP 429 with `Retry-After` header. |
| `UT-11-02` | `TenantRateLimiterPolicy` | Authenticated tenant exceeding burst token bucket receives 429; other tenants remain unaffected. |
| `UT-11-03` | `DeploymentWebhookRateLimiter` | High-frequency webhook deliveries from single `ApplicationId` are throttled without dropping concurrent apps. |
| `UT-11-04` | `EnvironmentValidationService` | In `Production` environment, using a dummy or short JWT/Encryption key throws `FatalStartupException`. |
| `UT-11-05` | `SecurityHeadersMiddleware` | Confirms HSTS, `X-Frame-Options: DENY`, and strict `Content-Security-Policy` on all HTTP responses. |

#### 11.6.2 High-Concurrency & Stress Tests (`APIHunter.Tests.Integration.Hardening`)
| Test ID | Test Target | Scenario & Expected Behavior |
|---|---|---|
| `IT-11-01` | `QueueConcurrencyStressTests` | 50 concurrent worker threads claiming from a 1,000-job queue: Exactly 1,000 jobs claimed, 0 duplicate claims, 0 deadlocks. |
| `IT-11-02` | `DatabaseDeadlockRegressionTests` | Concurrent execution of Campaign Dispatch and Finding Ingestion under load completes with 0 transaction deadlock errors. |
| `IT-11-03` | `DisasterRecoveryRestoreTests` | Full backup dump restored to a test database; verifies data parity and secret decryption success. |
| `IT-11-04` | `ScannerSandboxBoundaryTests` | Simulates container execution attempting network egress outside proxy port; confirms immediate socket drop. |
| `IT-11-05` | `ScannerAdapterContractHarness` | Executes contract suite against all registered scanner adapters to guarantee zero file residue on cancellation. |

---

## 4. Step-by-Step Implementation Sequence

```text
STEP 10.1: Telemetry, Metrics & Distributed Tracing
  ├── OpenTelemetry ActivitySource integration
  ├── Prometheus metrics collector (Jobs, Workers, Queues, AI)
  └── Sanitized structured logger

STEP 10.2: Autonomous Incident Engine
  ├── EF Core Migration: operational_incidents & ai_operational_diagnoses
  ├── IncidentEngineWorker background service
  └── Self-healing lease recovery & stall unfreezing

STEP 10.3: AI Operational Diagnosis Engine
  ├── IOperationalPromptSanitizer
  ├── AiOperationalDiagnosisService (IAiGateway integration)
  └── Deterministic fallback diagnostic engine

STEP 10.4: Operations Dashboard UI
  ├── /api/v1/operations REST endpoints (RBAC: Admin)
  └── Next.js 16 /operations dashboard (Fleet, Incidents, AI Drawer)

STEP 11.1: Multi-Tier Rate Limiting & Security Headers
  ├── ASP.NET Core RateLimiter policies (IP, Auth, Tenant, Webhook)
  └── Security headers middleware (HSTS, CSP, X-Frame-Options)

STEP 11.2: Automated Backup, PITR & Disaster Recovery
  ├── Backup & PITR scripts (PostgreSQL + Key ring)
  └── Disaster Recovery Runbook & Verification test

STEP 11.3: Concurrency Benchmarking & DB Optimization
  ├── 1,000-job concurrent claim stress test
  └── EXPLAIN ANALYZE index optimization & connection pooling

STEP 11.4: Scanner Sandbox Hardening & Adapter Contract Tests
  ├── Docker sandbox security configuration (cgroups, non-root, seccomp)
  └── Reusable ScannerAdapterContractTests harness

STEP 11.5: Final Production Readiness & Release Gate
  ├── Startup environment validator (Fail-closed on weak keys)
  ├── /health/live & /health/ready probes
  └── Full system regression & build verification
```

---

## 5. Definition of Done (DoD) Checklist

For each step in Phase 10 and Phase 11, the following gates must pass:
- [x] **Domain Model & Migration:** EF Core entities created with PostgreSQL migration and rollback compatibility.
- [x] **Security & Tenant Isolation:** Strict tenant boundary enforcement (`TenantId` isolation, zero token disclosure).
- [x] **Application & API Layer:** Service interfaces, dependency injection, and REST controllers with authorization.
- [x] **Unit Test Suite:** 100% passing unit tests covering edge cases, error handling, and deterministic fallbacks.
- [x] **Integration Test Suite:** Real PostgreSQL tests for concurrency, atomic transactions, and rollback behavior.
- [x] **Frontend UI & Build:** Next.js pages fully responsive with zero build errors (`npm run build` static generation passes).
- [x] **Documentation:** Blueprint, API schema, and disaster recovery runbooks synchronized.
