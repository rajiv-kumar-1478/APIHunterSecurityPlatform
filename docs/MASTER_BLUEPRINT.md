# APIHunter Security Platform — Complete Master Blueprint (Phases 1–11)

**Reference:** Phase 1 → Final Phase 11  
**Current Position:** Phase 6 Step 3 Complete  
**Next Immediate Step:** Phase 6 Step 4 (Multi-Snapshot Exposure Analysis)  
**APIHunterV2 Constraint:** Independent system; must remain isolated unless explicitly approved.

---

# 0. Executive Architecture

The complete system evolves through this pipeline across 11 phases:

```text
                         APIHunterV2
                             │
                             │ discovery/sync
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                    APIHunter Security Platform                   │
│                                                                  │
│  PHASE 1       PHASE 2        PHASE 3        PHASE 4             │
│  Foundation ──► Secret ──────► Deterministic ─► AI Investigation │
│                  Storage        Discovery                         │
│                                      │             │              │
│                                      └──────┬──────┘              │
│                                             ▼                     │
│                                      Security Graph               │
│                                             │                     │
│                                      PHASE 5                      │
│                                             ▼                     │
│                                  Credential Validation            │
│                                             │                     │
│                                             ▼                     │
│                                  Validation Truth                 │
│                                             │                     │
│                                      PHASE 6                      │
│                                             ▼                     │
│                               Security Intelligence & Risk        │
│                                             │                     │
│               ┌─────────────────────────────┼────────────────┐    │
│               ▼                             ▼                ▼    │
│            Findings                       Risk            History │
│               │                             │                │    │
│               └──────────────┬──────────────┴────────────────┘    │
│                              ▼                                    │
│  PHASE 7                 PHASE 8                 PHASE 9          │
│  Remediation ──────────► Continuous ───────────► Advanced         │
│  & SecOps                Monitoring              Intelligence     │
│                              │                       │            │
│                              └───────────┬───────────┘            │
│                                          ▼                        │
│                          PHASE 10               PHASE 11          │
│                          Enterprise Security ──► Production       │
│                          Center & Reporting      Hardening & Scale│
└──────────────────────────────────────────────────────────────────┘
```

---

# 1. Phase 1 — Platform Foundation

## Objective

Build the basic platform on which every later phase operates.

```text
Phase 1
│
├── Domain architecture
├── Application architecture
├── Infrastructure
├── PostgreSQL persistence
├── REST API
├── Background workers
├── Configuration
├── Authentication/authorization
├── Audit infrastructure
├── Notification infrastructure
└── Common job execution infrastructure
```

### 1.1 Layered Architecture
`Platform.Domain` → `Platform.Application` → `Platform.Infrastructure` → `Platform.Api` / `Platform.Worker`

### 1.2 Core Persistence & Durable Worker Model
Database-backed `AnalysisJob` queue. Uses `ClaimToken`, heartbeat, lease fencing, and PostgreSQL `FOR UPDATE SKIP LOCKED`.

### 1.3 Audit & Notification System
Establishes `AuditEvent` tracking and `INotificationService` abstractions (Email, Telegram).

---

# 2. Phase 2 — Secure Credential / Secret Storage Foundation

## Objective

Create the secure model for storing discovered credential candidates (`CredentialCandidate`).

### 2.1 Credential Lifecycle
`Detected` → `Triaged` → `Resolved`. (Validation does **not** mutate candidate status).

### 2.2 Secret Representation & Encryption Architecture
Uses ASP.NET Core Data Protection (`Platform.SecretCandidate.RawValue`). `MaskedValue` is exposed for UI/logs, `EncryptedRawValue` is secured at rest.

### 2.3 Secret Security Boundary
Raw secrets MUST NEVER enter logs, telemetry, audit events, AI prompts, graph labels, graph metadata, security findings, risk breakdown, browser storage, URLs, or normal API responses.

---

# 3. Phase 3 — Deterministic Security Discovery

## Objective

Build the deterministic repository analysis layer and APIHunter sync integration.

### 3.1 Deterministic Detector
Regex & rule-based pattern matching on `RepositorySnapshot` / `SnapshotFile`.

### 3.2 Discovery Provenance & APIHunterV2 Isolation
`DiscoveryType`: `ApiHunterSync`, `DeterministicDetector`, `AiInvestigator`, `CredentialValidation`, `AdminManual`.  
`APIHunterV2` remains 100% clean and isolated.

---

# 4. Phase 4 — AI Investigation & Security Intelligence Graph

## Objective

Add contextual intelligence and graph relationships. AI generates evidence; it is NOT the final security authority.

### 4.1 AI Provider Architecture & Model Router
Multi-provider support (`OpenAI`, `Anthropic`, `DeepSeek`, `Groq`). `AiModelRouter` manages fallbacks, rate-limit resets, and cooldowns.

### 4.2 Durable 10-Stage Investigation & Resource Controls
Staged execution with checkpoints: `RepositoryMetadata` (1) through `FinalIntelligenceReport` (10). Atomic lease fencing prevents stale worker updates.

### 4.3 Security Intelligence Graph
`SecurityIntelligenceNode` and `SecurityIntelligenceEdge` entities with deterministic naming conventions (`repo:{id}`, `candidate:{id}`, `service:{repoId}:{name}`, `env:{repoId}:{env}`, `db:{host}`, `domain:{domain}`).

---

# 5. Phase 5 — Credential Validation Engine

## Objective

Determine provider-level truth: "Is this discovered credential actually live and valid?"

### 5.1 Critical Separation of Truth
- `CredentialCandidate.Status` = Discovery/triage lifecycle state.
- `CredentialValidationResult.Status` = Live provider validation truth (`Valid`, `ValidInsufficientScope`, `Invalid`, `Expired`, `Revoked`, `RateLimited`, `Unavailable`, `Unsupported`, `BlockedByPolicy`).

### 5.2 SSRF Protection & Server-Controlled Endpoint Registry
Validation endpoints are hardcoded in `ValidationEndpointRegistry`. `SsrfProtectionService` resolves DNS, validates IP safety against private/loopback ranges, pins IP sockets, and validates TLS hostnames.

### 5.3 Durable Worker & Historical Audit
Reuses `AnalysisJob` with `JobType = CredentialValidation`. Retains full attempt history without overwriting past validation results.

---

# 6. Phase 6 — Security Intelligence, Risk & Continuous Verification

Convert discovery, graph, and validation evidence into actionable security findings and deterministic risk posture.

### 6.1 Step 1 — Security Finding Model ✅
- `SecurityFinding` (1:N) `SecurityFindingEvidence`.
- Canonical finding fingerprint: `SHA256(RepositoryId + FindingType + CoreEntityId)`.
- Canonical evidence fingerprint: `SHA256(FindingId + EvidenceType + SourceEntityId)`.

### 6.2 Step 2 — Deterministic Risk Engine ✅
- **Formula:** $\text{RawScore} = \text{BaseFloor} + \sum \text{PositiveFactors} + \sum \text{NegativeFactors}$; $\text{FinalScore} = \text{clamp}(\text{RawScore}, 0, 100)$.
- **Base Floors:** `ValidatedCredentialExposed` (40), `ProductionServiceExposed` (30), `DatabaseExposure` (30), `UnvalidatedCredentialExposed` (20), `HistoricalExposureDetected` (15), `OverprivilegedCredential` (15).
- **Factors:** `CREDENTIAL_VALID` (+30), `CREDENTIAL_VALID_LIMITED` (+20), `PRODUCTION_ENV` (+20), `PRODUCTION_DB` (+20), `INTERNET_FACING` (+15), `HISTORICAL_COMMIT` (+10), `AI_HIGH_CONFIDENCE` (+10), `MULTI_SOURCE` (+5), `CREDENTIAL_REVOKED` (-30).
- **Repository Risk:** Max active score + $0.25 \times$ secondary active scores. Excludes `Remediated`, `AcceptedRisk`, `FalsePositive`, `Resolved`.

### 6.3 Step 3 — Graph Intelligence Engine ✅
- Read-only consumer of graph nodes/edges.
- Strict repository boundary scoping (`repo:{id}` 1-hop subgraph).
- Finding identity based on stable `Node.Id` (Guid), not labels.
- `INTERNET_FACING` requires explicit `Domain ←[AssociatedWith]→ Repo ←[BelongsTo]─ Service` edge chain.
- Allowlist-only `SafeEvidenceJson` projection.
- Zero direct dependency on `RiskEngine`.

### 6.4 Step 4 — Multi-Snapshot Exposure Analysis ⏳ (NEXT)
Determine historical exposure persistence across repository snapshot history without creating duplicate snapshot engines.

### 6.5 Step 5 — Finding Lifecycle Governance ⏳
State machine governance (`Open` → `Investigating` → `Confirmed` → `Remediated` / `AcceptedRisk` / `FalsePositive` / `Resolved`).

### 6.6 Step 6 — Continuous Revalidation ⏳
Background automated re-validation of active credentials via `AnalysisJob`.

### 6.7 Step 7 — Alerting ⏳
Trigger security alerts based on finding/risk state changes via `INotificationService`.

### 6.8 Step 8 — Security Center Dashboard ⏳
Unified UI dashboard displaying posture, findings, graph, validation history, and risk breakdowns.

### 6.9 Step 9 — Final Exit Gate ⏳
Comprehensive verification (build, unit/integration tests, secret scans, APIHunter clean tree).

---

# 7. Phase 7 — Remediation & Security Operations

## Objective
Move from detection/intelligence into actionable security operations and remediation.

### 7.1 Remediation Model (`SecurityRemediation`)
Tracks recommended actions, owners, priorities, due dates, statuses (`Pending`, `Assigned`, `InProgress`, `Blocked`, `Completed`, `Verified`, `Rejected`), and completion evidence.

### 7.2 Human Approval Boundary & Verification
AI provides remediation recommendations; human operators authorize changes. Remediation is verified via repository rescan and credential re-validation. Reuses existing `AnalysisJob` queue and audit events.

---

# 8. Phase 8 — Continuous Repository Monitoring

## Objective
Transform snapshot analysis into event-driven and incremental repository monitoring.

### 8.1 Incremental Scanning & Event Pipeline
Scans only changed files between commits to minimize computation/AI costs. Monitors webhooks and repository events (commits, PRs, tags).

### 8.2 Change-Triggered Revalidation
Triggers targeted candidate revalidation and finding risk recalculations when repository changes alter security posture.

---

# 9. Phase 9 — Advanced Security Intelligence & Correlation

## Objective
Elevate graph intelligence into multi-hop attack path analysis and cross-source correlation.

### 9.1 Attack-Path Analysis (`SecurityAttackPath`)
Identifies multi-hop exposure paths (e.g., `Credential` → `Repository` → `Internet-facing Service` → `Production Database`).

### 9.2 Cross-Source Correlation & Systemic Risk
Correlates findings across repositories and organizations to identify shared credentials and systemic risk patterns.

---

# 10. Phase 10 — Enterprise Security Center & Reporting

## Objective
Provide an enterprise-grade security operations dashboard, reporting engine, and executive visibility.

### 10.1 Dashboards & Interactive Graph
Executive posture overviews, repository security drill-downs, interactive filtering, and transparent risk score factor breakdowns.

### 10.2 Scheduled & Exportable Reporting
Generate PDF/CSV/JSON security reports delivered via `INotificationService`.

---

# 11. Phase 11 — Production Hardening, Scale & Final Platform

## Objective
Perform final production hardening, scalability optimizations, performance tuning, and security audits.

### 11.1 Scalability & Performance Tuning
Horizontal worker scaling with claim-token fencing, database query/indexing optimization, and strict retention policy enforcement.

### 11.2 Disaster Recovery, Observability & Final Exit Gate
Comprehensive DR testing, telemetry (zero raw secrets), third-party dependency auditing, penetration testing, and final platform exit verification.

---

# 12. Complete Phase Status Map

| Phase | Purpose | Output | Status |
|---|---|---|---|
| **Phase 1** | Platform Foundation | API, DB, workers, auth, audit, notifications | ✅ Complete |
| **Phase 2** | Secure Credential Storage | Encrypted `CredentialCandidate` | ✅ Complete |
| **Phase 3** | Deterministic Discovery | Secret detection + APIHunter sync | ✅ Complete |
| **Phase 4** | AI Investigation & Graph | AI evidence + Security Graph | ✅ Complete |
| **Phase 5** | Credential Validation | Live provider validation + SSRF defense | ✅ Complete |
| **6.1** | Security Finding Model | `SecurityFinding` & evidence schema | ✅ Complete |
| **6.2** | Deterministic Risk Engine | 0–100 explainable risk engine | ✅ Complete |
| **6.3** | Graph Intelligence Engine | Graph → Findings correlation | ✅ Complete |
| **6.4** | Multi-Snapshot Exposure | Snapshot history & persistence analysis | ⏳ **NEXT** |
| **6.5** | Finding Lifecycle Governance | Finding state machine & audit | 🔒 Pending |
| **6.6** | Continuous Revalidation | Scheduled validation jobs | 🔒 Pending |
| **6.7** | Alerting | Security notifications | 🔒 Pending |
| **6.8** | Security Center | Security dashboard UI | 🔒 Pending |
| **6.9** | Final Exit Gate | Phase 6 verification & exit gate | 🔒 Pending |
| **Phase 7** | Remediation & SecOps | Remediation tracking & workflow | 🔒 Pending |
| **Phase 8** | Continuous Monitoring | Webhooks & incremental scanning | 🔒 Pending |
| **Phase 9** | Advanced Intelligence | Attack path analysis & correlation | 🔒 Pending |
| **Phase 10** | Enterprise Security Center | Executive reporting & dashboards | 🔒 Pending |
| **Phase 11** | Production Hardening | Scale, DR, perf & final release | 🔒 Pending |

---

# 13. Project-Wide Invariants & Core Rules

1. **APIHunterV2 Isolation:** APIHunterV2 is an independent system; never modify it.
2. **Reuse Platform Infrastructure:** Never create duplicate queues, workers, encryption, or notification frameworks.
3. **AI is Evidence, Not Authority:** Risk scores, validation statuses, and finding governance are strictly deterministic.
4. **Credential Candidate Status Immutability:** `CandidateStatus` tracks discovery/triage only. Validation truth lives exclusively in `CredentialValidationResult`.
5. **Provenance Preservation:** Always preserve discovery source (`ApiHunterSync`, `DeterministicDetector`, `AiInvestigator`, `CredentialValidation`).
6. **Zero Raw Secret Exposure:** Raw secrets MUST NOT appear in logs, telemetry, audit records, AI prompts, graph labels, graph metadata, findings, risk breakdowns, API responses, or browser storage.
7. **Worker Lease Fencing:** All background worker updates must use `ClaimToken` concurrency fencing.
8. **Idempotency & Fingerprinting:** All findings and evidence use deterministic SHA256 fingerprints.
9. **Queryable History:** Never overwrite historical validation or finding evidence.
10. **Phase Gate Governance:** Every phase step requires review and verification before proceeding.
