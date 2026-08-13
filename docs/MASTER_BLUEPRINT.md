# APIHunter Security Platform — Complete Master Blueprint

**Reference:** Phase 1 → Final Phase 6
**Current position:** Phase 6 Step 3 complete
**Next:** Phase 6 Step 4
**APIHunterV2:** Independent system; must remain isolated unless explicitly approved

---

# 0. Executive Architecture

The complete system is intended to evolve through this pipeline:

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
│                               Security Intelligence               │
│                                             │                     │
│                    ┌────────────────────────┼───────────────┐     │
│                    ▼                        ▼               ▼     │
│                 Findings                  Risk           History  │
│                    │                        │               │     │
│                    └───────────────┬────────┴───────────────┘     │
│                                    ▼                             │
│                         Continuous Verification                   │
│                                    │                             │
│                                    ▼                             │
│                              Alerting                             │
│                                    │                             │
│                                    ▼                             │
│                           Security Center                         │
└──────────────────────────────────────────────────────────────────┘
```

---

# 1. Phase 1 — Platform Foundation

## Objective

Build the basic platform on which every later phase operates.

The purpose of Phase 1 is **not security intelligence** yet. It establishes the application infrastructure.

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

---

## 1.1 Layered architecture

```text
Platform.Domain
       │
       ▼
Platform.Application
       │
       ▼
Platform.Infrastructure
       │
       ├──────────────► PostgreSQL
       │
       └──────────────► External Services
       │
       ▼
Platform.Api
       │
       ▼
Next.js Dashboard

Platform.Worker
       │
       └──────────────► Background processing
```

---

## 1.2 Core persistence

Phase 1 establishes the database infrastructure and the general repository/job model used later.

The important architectural idea is:

```text
Database
   │
   ├── repositories
   ├── users/auth
   ├── audit
   ├── notifications
   └── AnalysisJob
```

`AnalysisJob` becomes particularly important later because Phase 5 reuses it rather than creating another queue.

---

## 1.3 Durable worker model

The platform uses database-backed durable jobs.

Conceptually:

```text
Producer
   │
   ▼
AnalysisJob
   │
   ▼
Worker claims job
   │
   ▼
Execute
   │
   ▼
Complete
```

Later phases add:

```text
ClaimToken
Heartbeat
Lease fencing
FOR UPDATE SKIP LOCKED
```

instead of inventing another worker architecture.

---

## 1.4 Audit system

The platform maintains auditable events for important actions.

Later phases depend on this for:

* AI investigation
* graph analysis
* validation
* risk changes
* finding lifecycle
* notifications

---

## 1.5 Notification system

Phase 1 establishes the notification abstraction that Phase 6 eventually consumes.

Conceptually:

```text
INotificationService
       │
       ├── Email
       └── Telegram
```

Phase 6 should therefore **reuse** this rather than create another notification framework.

---

# 2. Phase 2 — Secure Credential / Secret Storage Foundation

## Objective

Create the secure model for storing discovered credential candidates.

The core object is:

```text
CredentialCandidate
```

A candidate means:

> Something that looks like a credential or security-sensitive value was discovered.

It does **not** mean the credential is valid.

---

## 2.1 Credential lifecycle

```text
Detected
   │
   ▼
Triaged
   │
   ▼
Resolved
```

This lifecycle remains the discovery lifecycle permanently.

Phase 5 validation does **not** change it.

---

## 2.2 Secret representation

The conceptual model is:

```text
CredentialCandidate
│
├── MaskedValue
│
├── EncryptedRawValue
│
├── Provider/type metadata
│
└── Discovery metadata
```

Example:

```text
MaskedValue:
sk-proj-****4321
```

The raw value remains encrypted.

---

## 2.3 Encryption architecture

The established mechanism is ASP.NET Core Data Protection.

Important purpose:

```text
Platform.SecretCandidate.RawValue
```

This became a formal architectural decision in Phase 5:

> Never introduce a second encryption mechanism just because a later design document says "AES-GCM."

Future components must reuse the established mechanism unless explicitly redesigning the security architecture.

---

## 2.4 Secret security boundary

Raw secrets must never enter:

```text
Logs
Telemetry
Audit events
AI prompts
Graph labels
Graph metadata
Security findings
Risk breakdown
Browser storage
URLs
Normal API responses
```

This becomes a global invariant for Phases 3–6.

---

# 3. Phase 3 — Deterministic Security Discovery

## Objective

Build the deterministic repository analysis layer.

This is the platform's baseline detection engine.

```text
Repository
    │
    ▼
Repository Snapshot
    │
    ▼
File Analysis
    │
    ▼
Deterministic Detection
    │
    ▼
CredentialCandidate
```

---

## 3.1 Deterministic detector

The deterministic detector uses known credential patterns/rules.

Conceptually:

```text
File
 │
 ├── pattern match
 ├── provider detection
 ├── normalization
 ├── masking
 └── candidate creation
```

The result becomes:

```text
CredentialCandidate
```

---

## 3.2 Discovery provenance

Every discovery should retain its source.

Later graph provenance includes:

```text
ApiHunterSync
DeterministicDetector
AiInvestigator
CredentialValidation
ManualReview
```

The principle is:

> New evidence enriches the security picture; it does not erase how something was originally discovered.

---

## 3.3 APIHunterV2 integration

APIHunterV2 already exists separately.

The intended architecture is:

```text
APIHunterV2
    │
    ▼
APIHunter synchronization
    │
    ▼
Security Platform
```

Not:

```text
Security Platform
       │
       └── modifies APIHunterV2
```

Therefore:

**APIHunterV2 must remain clean and isolated.**

This is an important project-wide constraint.

---

## 3.4 Phase 3 output

By the end of Phase 3, the platform should be able to answer:

> "What potentially sensitive credentials did we discover, where were they found, and how were they discovered?"

It cannot yet reliably answer:

> "Is the credential actually valid?"

That belongs to Phase 5.

---

# 4. Phase 4 — AI Investigation & Security Intelligence Graph

Phase 4 adds contextual intelligence.

The important architectural rule is:

> AI is an evidence generator, not the final security authority.

---

## 4.1 Phase 4 architecture

```text
Repository
    │
    ▼
AI Investigation Job
    │
    ▼
AiInvestigationEngine
    │
    ├── Repository metadata
    ├── File inventory
    ├── Technology identification
    ├── APIHunter investigation
    ├── Configuration analysis
    ├── Candidate discovery
    ├── Cross-file relationships
    ├── Credential/service relationships
    ├── Production exposure
    └── Final intelligence
    │
    ▼
AI Evidence
    │
    ▼
Security Intelligence Graph
```

---

## 4.2 AI provider architecture

Supported providers introduced during Phase 4 include:

```text
OpenAI
Anthropic
DeepSeek
Groq
```

Architecture:

```text
IAiProvider
    │
    ├── OpenAI adapter
    ├── Anthropic adapter
    ├── DeepSeek adapter
    └── Groq adapter
```

The adapter is responsible for communicating with its provider.

The router is responsible for model/provider selection.

---

## 4.3 AI model router

Conceptually:

```text
AiModelRouter
│
├── enabled?
├── priority
├── health
├── capability
├── rate limit
├── cooldown
└── fallback
```

Important distinction:

```text
HTTP 429
   ↓
RateLimitResetAtUtc

Generic transient failure
   ↓
CooldownUntilUtc
```

These must not be conflated.

---

## 4.4 AI investigation durability

The investigation is staged.

```text
Stage 1
   ↓
Checkpoint
   ↓
Stage 2
   ↓
Checkpoint
   ↓
...
Stage 10
```

Current ten-stage model:

```text
1. RepositoryMetadata
2. FileInventory
3. TechnologyIdentification
4. ApiHunterSeedInvestigation
5. ConfigurationAnalysis
6. CandidateDiscovery
7. CrossFileRelationshipAnalysis
8. CredentialServiceRelationshipAnalysis
9. ProductionExposureAnalysis
10. FinalIntelligenceReport
```

If the worker crashes, the investigation resumes from its durable checkpoint.

---

## 4.5 AI resource controls

The engine has runtime limits:

```text
MaxFilesPerInvestigation       = 50
MaxFileSizeBytes               = 1 MB
MaxAiCallsPerInvestigation    = 20
MaxTokensPerInvestigation     = 100,000
MaxStageRetries               = 3
MaxInvestigationDuration      = 30 minutes
```

These limits protect both cost and execution safety.

---

## 4.6 Worker fencing

AI jobs use atomic lease fencing.

Conceptually:

```sql
UPDATE ai_investigation_jobs
SET ...
WHERE id = @jobId
AND claim_token = @originalClaimToken;
```

If another worker owns the job, the stale worker cannot update it.

This pattern later becomes a reusable platform-wide worker safety model.

---

## 4.7 Security Intelligence Graph

Phase 4 introduces:

```text
SecurityIntelligenceNode
SecurityIntelligenceEdge
```

Nodes include:

```text
Repository
CredentialCandidate
Domain
Database
Service
Environment
```

Example:

```text
Credential
    │
    ├── AppearsIn ──► Repository
    │
    └── RelatedTo ──► Service
                         │
                         ▼
                    Environment
                         │
                         ▼
                     Database
```

---

## 4.8 Graph identity

Nodes use deterministic identities.

Examples:

```text
repo:{repositoryId}

candidate:{candidateId}

domain:{normalizedDomain}

db:{normalizedHost}

service:{repositoryId}:{normalizedServiceName}

env:{repositoryId}:{environment}
```

Edges are identified by:

```text
SourceNodeId
TargetNodeId
EdgeType
```

This prevents duplicate relationships.

---

## 4.9 Graph history

Nodes and edges preserve:

```text
FirstObservedAtUtc
LastObservedAtUtc
```

This becomes important for historical analysis later.

---

# 5. Phase 5 — Credential Validation Engine

Phase 5 answers:

> "Is this discovered credential actually valid?"

It does not change the discovery lifecycle.

---

## 5.1 Validation architecture

```text
CredentialCandidate
       │
       ▼
ValidationEndpointRegistry
       │
       ▼
SSRF Protection
       │
       ▼
Provider Validator
       │
       ▼
CredentialValidationResult
```

---

## 5.2 Validation statuses

```text
Unknown
Pending
Valid
ValidInsufficientScope
Invalid
Expired
Revoked
RateLimited
Unavailable
Unsupported
BlockedByPolicy
ValidationError
```

---

## 5.3 Critical separation

```text
CredentialCandidate.Status
        │
        └── discovery lifecycle

CredentialValidationResult.Status
        │
        └── provider validation truth
```

Never merge them.

---

## 5.4 Validation endpoint registry

The candidate cannot provide the validation destination.

Instead:

```text
Provider
   │
   ▼
ValidationEndpointRegistry
   │
   ▼
Fixed server-controlled endpoint
```

Supported endpoints include:

```text
OpenAI
Anthropic
GitHub
AWS STS
Stripe
SendGrid
Mailgun
DeepSeek
Groq
Slack
```

Candidate-provided:

```text
URL
Host
Port
Scheme
```

must not control validation.

---

## 5.5 SSRF defense

Validation performs:

```text
DNS lookup
   │
   ▼
Resolve ALL A/AAAA
   │
   ▼
Check every address
   │
   ▼
Block private/loopback/metadata/etc.
   │
   ▼
Pin TCP connection to validated IP
   │
   ▼
TLS using original hostname
```

This prevents DNS-rebinding TOCTOU attacks.

---

## 5.6 Provider validators

Current validator architecture:

```text
BaseCredentialValidator
        │
        ├── OpenAI
        ├── Anthropic
        ├── DeepSeek
        ├── Groq
        ├── AWS STS
        ├── GitHub
        ├── Stripe
        ├── SendGrid
        ├── Mailgun
        └── Slack
```

Unsupported providers:

```text
FallbackCredentialValidator
        │
        ▼
Unsupported
        │
        ▼
NO network call
```

---

## 5.7 Durable validation worker

Validation reuses:

```text
AnalysisJob
```

with:

```text
JobType = CredentialValidation
```

Architecture:

```text
AnalysisJob
    │
    ▼
FOR UPDATE SKIP LOCKED
    │
    ▼
ClaimToken
    │
    ▼
CredentialValidationWorker
    │
    ▼
CredentialValidationService
    │
    ▼
Provider Validator
```

No second queue is introduced.

---

## 5.8 Validation history

Every validation attempt creates a historical result.

```text
Attempt 1 → Valid
Attempt 2 → Valid
Attempt 3 → RateLimited
Attempt 4 → Revoked
```

This history is preserved.

---

## 5.9 Phase 5 graph enrichment

Validation enriches existing graph nodes.

```text
CredentialNode
      │
      ▼
latestValidationStatus
isCurrentlyValidated
latestValidatedAtUtc
latestValidationConfidence
```

It does not create duplicate credential nodes.

---

## 5.10 Phase 5 dashboard

The `/credentials` page provides:

* masked credential inventory
* validation status
* provenance
* validation history
* safe evidence
* graph preview
* admin "Validate Now"

Raw secrets never reach the browser.

---

# 6. Phase 6 — Security Intelligence, Risk & Continuous Verification

Phase 6 converts all previous evidence into actionable security conclusions.

```text
Phase 4 Graph
      +
Phase 5 Validation
      +
Phase 3 Discovery
      +
Historical Snapshots
      ↓
Phase 6
      ↓
Security Findings
      ↓
Risk
      ↓
Lifecycle
      ↓
Continuous Verification
      ↓
Alerts
      ↓
Security Center
```

---

# 7. Phase 6 Step 1 — Security Finding Model

Implemented and locked.

Core entity:

```text
SecurityFinding
```

Supporting entity:

```text
SecurityFindingEvidence
```

Relationship:

```text
SecurityFinding
      │
      └──── 1:N ──── SecurityFindingEvidence
```

---

## 7.1 Finding types

```text
ValidatedCredentialExposed
UnvalidatedCredentialExposed
ProductionServiceExposed
HistoricalExposureDetected
OverprivilegedCredential
DatabaseExposure
```

---

## 7.2 Finding lifecycle

```text
Open
 │
 ▼
Investigating
 │
 ▼
Confirmed
 │
 ├──► Remediated
 ├──► AcceptedRisk
 ├──► FalsePositive
 └──► Resolved
```

Findings are never hard deleted.

---

## 7.3 Finding fingerprint

```text
SHA256(
    RepositoryId +
    FindingType +
    CoreEntityId
)
```

This prevents repeated analysis from creating duplicate findings.

---

## 7.4 Evidence fingerprint

```text
SHA256(
    FindingId +
    EvidenceType +
    SourceEntityId
)
```

This prevents repeated evidence attachment from creating duplicates.

---

# 8. Phase 6 Step 2 — Deterministic Risk Engine

Implemented and locked.

The most important rule:

> **AI does not calculate final risk.**

The deterministic risk engine does.

---

## 8.1 Risk factors

```text
CREDENTIAL_VALID       +30
CREDENTIAL_VALID_LIMITED +20
PRODUCTION_ENV         +20
PRODUCTION_DB          +20
INTERNET_FACING        +15
HISTORICAL_COMMIT      +10
AI_HIGH_CONFIDENCE     +10
MULTI_SOURCE           +5
CREDENTIAL_REVOKED     -30
```

---

## 8.2 Base floors

```text
ValidatedCredentialExposed       40
ProductionServiceExposed         30
DatabaseExposure                  30
UnvalidatedCredentialExposed     20
HistoricalExposureDetected       15
OverprivilegedCredential         15
```

---

## 8.3 Final score

```text
RawScore = BaseFloor + Σ(PositiveFactors) + Σ(NegativeFactors)

FinalScore = Clamp(RawScore, 0, 100)
```

---

## 8.4 Severity thresholds

```text
80–100  Critical
60–79   High
35–59   Medium
0–34    Low
```

Algorithm version:

```text
v1.0
```

The factor breakdown is persisted so every score is explainable.

---

## 8.5 Repository risk

Only active findings count:

```text
Open
Investigating
Confirmed
```

Resolved/remediated/accepted/false-positive findings contribute zero active risk.

Formula:

```text
RepositoryScore =
min(
    100,
    MaxActiveScore +
    Σ(0.25 × OtherActiveScores)
)
```

---

## 8.6 Mathematical consistency example

```text
ValidatedCredentialExposed (Base 40) + PRODUCTION_ENV (+20) + INTERNET_FACING (+15):

  When Valid (+30):     40 + 30 + 20 + 15 = 105 → clamped 100 (Critical)
  When Revoked (-30):   40 + 20 + 15 - 30 = 45           (Medium)

ValidInsufficientScope is differentiated:
  Valid:                +30
  ValidInsufficientScope: +20
```

---

# 9. Phase 6 Step 3 — Graph Intelligence Engine

Complete and locked.

Architecture:

```text
Security Intelligence Graph
            │
            │ READ ONLY
            ▼
GraphIntelligenceEngine
            │
            ▼
SecurityFindingService
            │
            ▼
RiskEngine
```

The graph builder remains unchanged.

The risk engine remains unchanged.

---

## 9.1 Patterns

### Validated credential

```text
CredentialCandidate
+
Valid/ValidInsufficientScope
→ ValidatedCredentialExposed
```

### Unvalidated credential

```text
CredentialCandidate
+
No usable validation
→ UnvalidatedCredentialExposed
```

### Production service

```text
Service
   │
   ▼
Repository
   │
   ▼
production Environment
```

### Database exposure

```text
Credential
   │
   ▼
Database
```

---

## 9.2 Important Step 3 corrections

Finding identity uses:

```text
Node.Id (Guid)
```

not:

```text
Node.Name
Node.Label
```

Repository boundaries are enforced (strict repo-scoped subgraph).

Internet-facing classification requires the explicit graph relationship chain:

```text
Domain ←[AssociatedWith]→ Repository ←[BelongsTo]─ Service
```

Evidence projection is allowlisted (never raw MetadataJson).

GraphIntelligenceEngine has zero RiskEngine dependency.

---

# 10. Phase 6 Step 4 — Multi-Snapshot Exposure Analysis

**Next step.**

Purpose:

> Determine whether credentials/security exposures existed historically and whether they persisted.

---

## 10.1 Architecture

```text
Repository
    │
    ▼
Existing RepositorySnapshots
    │
    ├── HEAD
    ├── 30 days
    ├── 90 days
    └── 180 days
    │
    ▼
ExposureAnalysisService
    │
    ▼
Historical exposure evidence
    │
    ▼
SecurityFinding
    │
    ▼
RiskEngine
```

---

## 10.2 Important constraint

Do **not** create a second snapshot system.

Reuse existing:

```text
RepositorySnapshot
SnapshotFile
```

and existing repository history mechanisms.

---

## 10.3 Example

```text
Commit A
  credential exposed

Commit B
  credential exposed

Commit C
  credential exposed

HEAD
  credential still exposed
```

The system can conclude:

```text
HistoricalExposureDetected
```

and potentially increase risk through:

```text
HISTORICAL_COMMIT +10
```

---

# 11. Phase 6 Step 5 — Finding Lifecycle Governance

Purpose:

Prevent arbitrary security finding state changes.

---

## 11.1 State machine

```text
Open
 ├── Investigating
 ├── Confirmed
 ├── FalsePositive
 └── AcceptedRisk

Investigating
 ├── Confirmed
 ├── FalsePositive
 └── AcceptedRisk

Confirmed
 ├── Remediated
 ├── AcceptedRisk
 └── FalsePositive

Remediated
 └── Resolved
```

---

## 11.2 Audit

Resolution records:

```text
ResolvedByUserId
ResolvedAtUtc
ResolutionReason
```

No hard delete.

---

# 12. Phase 6 Step 6 — Continuous Revalidation

Purpose:

> Automatically re-check credentials that are still relevant.

Architecture:

```text
Active Credential
       │
       ▼
ContinuousRevalidationWorker
       │
       ▼
AnalysisJob
       │
       ▼
CredentialValidationWorker
       │
       ▼
CredentialValidationResult
       │
       ▼
Status changed?
       │
       ├── No
       │
       └── Yes
             │
             ▼
        Graph update
             │
             ▼
        Finding update
             │
             ▼
        Risk recalculation
             │
             ▼
        Audit event
             │
             ▼
          Alerting
```

---

# 13. Phase 6 Step 7 — Alerting

Use the Phase 1 notification abstraction.

Do not create another notification system.

Potential alerts:

```text
Critical finding created
High finding created
Valid credential detected
Valid credential becomes revoked
Invalid credential becomes valid
Production credential exposure
Production database exposure
Historical exposure discovered
```

The alert decision must come from deterministic findings/risk.

---

# 14. Phase 6 Step 8 — Security Center

Final dashboard:

```text
Security Center
│
├── Overall Risk Score
├── Risk Trend
├── Critical Findings
├── High Findings
├── Medium/Low Findings
├── Credential Status
├── Historical Exposure
├── Security Graph
├── Finding Evidence
├── Risk Factors
├── Lifecycle
└── Notifications
```

---

# 15. Phase 6 Step 9 — Final Exit Gate

The entire project is only considered complete after:

### Backend

```text
dotnet build
0 warnings
0 errors
```

### Tests

```text
dotnet test
All passed
```

### Frontend

```text
npm run build
Successful
```

### Security

```text
Secret scan
    ↓
Zero raw secrets
```

### APIHunter

```text
APIHunterV2
    ↓
Clean working tree
```

### Architecture

Verify:

```text
No duplicate queue
No duplicate encryption
No AI risk authority
No candidate status mutation
No provenance destruction
No SSRF bypass
No stale worker mutation
No secret leakage
```

---

# 16. Complete Phase Map

| Phase       | Purpose                   | Key Output                               | Status |
| ----------- | ------------------------- | ---------------------------------------- | ------ |
| **Phase 1** | Platform Foundation       | API, DB, workers, audit, notifications   | ✅      |
| **Phase 2** | Secure Credential Storage | `CredentialCandidate`, encryption        | ✅      |
| **Phase 3** | Deterministic Discovery   | Secret detection + APIHunter integration | ✅      |
| **Phase 4** | AI Investigation & Graph  | AI evidence + security graph             | ✅      |
| **Phase 5** | Credential Validation     | Provider validation + SSRF protection    | ✅      |
| **6.1**     | Security Findings         | Finding + Evidence architecture          | ✅      |
| **6.2**     | Risk Engine               | Deterministic 0–100 risk                 | ✅      |
| **6.3**     | Graph Intelligence        | Graph → Findings                         | ✅      |
| **6.4**     | Historical Exposure       | Snapshot/history analysis                | ⏳ Next |
| **6.5**     | Finding Governance        | Lifecycle state machine                  | ⏳      |
| **6.6**     | Continuous Verification   | Automatic revalidation                   | ⏳      |
| **6.7**     | Alerting                  | Security notifications                   | ⏳      |
| **6.8**     | Security Center           | Final security dashboard                 | ⏳      |
| **6.9**     | Exit Gate                 | Full verification + release              | ⏳      |

---

# 17. The Most Important Data Flow

This should be treated as the project's canonical flow:

```text
┌──────────────────┐
│   APIHunterV2    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Deterministic    │
│ Discovery        │
└────────┬─────────┘
         │
         ▼
┌────────────────────────┐
│ CredentialCandidate    │
│ "Something suspicious" │
└───────────┬────────────┘
            │
            ├──────────────► AI Investigation
            │                       │
            │                       ▼
            │                Security Graph
            │
            ▼
┌────────────────────────┐
│ Credential Validation  │
│ "Is it actually valid?"│
└───────────┬────────────┘
            │
            ▼
┌─────────────────────────────┐
│ CredentialValidationResult  │
│ Historical provider truth   │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ Graph Intelligence Engine   │
│ Correlates relationships     │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ SecurityFinding             │
│ "What security problem?"    │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ Deterministic Risk Engine   │
│ "How dangerous?"            │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ Repository Risk             │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ Continuous Verification     │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ Alerts + Security Center    │
└─────────────────────────────┘
```

---

# 18. Project-Wide "Do Not Break" Rules

These are now the most important reference rules for future implementation.

### Rule 1 — Don't modify APIHunterV2 casually

APIHunterV2 is an independent source/integration.

### Rule 2 — Don't create duplicate infrastructure

Before creating anything new, check whether the platform already has:

* queue
* worker
* encryption
* audit
* notifications
* snapshot
* graph
* repository
* authentication

### Rule 3 — Never make AI the security authority

AI produces evidence.

Deterministic policy decides:

```text
validation
risk
severity
lifecycle rules
```

where applicable.

### Rule 4 — Never mutate discovery status during validation

```text
CredentialCandidate.Status
```

remains discovery lifecycle.

### Rule 5 — Never destroy provenance

Existing:

```text
APIHunter
Deterministic
AI
Validation
```

sources must remain distinguishable.

### Rule 6 — Never expose raw credentials

Not in:

```text
DB evidence
API
UI
Graph
AI
Logs
Audit
Telemetry
Risk JSON
```

### Rule 7 — Worker mutations must be fenced

Use existing `ClaimToken`/EF concurrency architecture.

### Rule 8 — New analysis must be idempotent

Use deterministic fingerprints/identities.

### Rule 9 — Historical information must remain queryable

Do not overwrite historical validation or finding evidence when new state arrives.

### Rule 10 — Every phase must stop at its exit gate

No automatic jump into the next phase.

---

# 19. Current Master Status

```text
PHASE 1
Platform Foundation
        ✅ COMPLETE

PHASE 2
Secure Credential Storage
        ✅ COMPLETE

PHASE 3
Deterministic Discovery
        ✅ COMPLETE

PHASE 4
AI Investigation + Security Graph
        ✅ COMPLETE / LOCKED

PHASE 5
Credential Validation Engine
        ✅ COMPLETE / LOCKED

PHASE 6.1
Security Finding Model
        ✅ COMPLETE / LOCKED

PHASE 6.2
Deterministic Risk Engine
        ✅ COMPLETE / LOCKED

PHASE 6.3
Graph Intelligence Engine
        ✅ COMPLETE / LOCKED

PHASE 6.4
Multi-Snapshot Exposure Analysis
        ⏳ NEXT

PHASE 6.5
Finding Lifecycle Governance
        ⏳

PHASE 6.6
Continuous Revalidation
        ⏳

PHASE 6.7
Alerting
        ⏳

PHASE 6.8
Security Center
        ⏳

PHASE 6.9
Final Exit Gate
        ⏳
```

---

> **Note:** Phase 1–3 are represented here at architectural level because their original
> detailed step-by-step completion reports are not present in the conversation context.
> If original Phase 1–3 reports are provided, they can be merged into this blueprint
> verbatim to make it the definitive implementation specification.
. AI Hallucination Protection

AI output must be validated against schemas.

```text
AI output
 ↓
JSON schema
 ↓
Evidence validator
 ↓
Business rules
 ↓
Store
```

If AI says:

```text
file = production.env
line = 5000
```

but that file/line does not exist:

```text
REJECT AI OBSERVATION
```

---

# 71. AI "I Don't Know" State

AI must be allowed to return:

```text
UNKNOWN
INSUFFICIENT_EVIDENCE
REQUIRES_VALIDATION
UNSUPPORTED
```

This is preferable to fabricated certainty.

---

# 72. AI Cost Optimization

Pipeline:

```text
cheap deterministic analysis
       ↓
small AI classification
       ↓
only important cases
       ↓
stronger AI investigation
```

For repositories:

```text
50,000 files
 ↓
classify
 ↓
5,000 relevant
 ↓
500 important chunks
 ↓
AI
```

Don't send everything to an expensive model.

---

# 73. Repository Snapshot Deduplication

Calculate:

```text
SHA-256(repository archive)
```

If already present:

```text
don't upload duplicate
```

Also identify individual file hashes.

This enables incremental analysis.

---

# 74. Website Scan Deduplication

For each asset:

```text
URL
Content hash
Last seen
```

If unchanged:

```text
skip expensive analysis
```

If changed:

```text
new analysis
```

---

# 75. Continuous Website Scheduler

Example:

```text
Website A → every 6 hours
Website B → every 12 hours
Website C → daily
```

Scheduler creates:

```text
WebsiteScanJob
```

not an infinite worker loop.

---

# 76. Important Failure Scenario

### APIHunter database unavailable

```text
APIHunter sync
 ↓
FAILED
 ↓
retry
```

Existing platform intelligence remains available.

---

# 77. AI Provider unavailable

```text
OpenAI unavailable
 ↓
DeepSeek
 ↓
Groq
```

If all unavailable:

```text
AI jobs → QUEUED
```

APIHunter continues working.

---

# 78. BugHunter unavailable

```text
BugHunter health = BROKEN

Website discovery
    ↓
continues where possible

BugHunter-dependent jobs
    ↓
QUEUED
```

Operations AI explains the problem.

---

# 79. R2 unavailable

```text
Large artifact upload
 ↓
retry
```

Do not lose database metadata.

Job becomes:

```text
WAITING_FOR_STORAGE
```

---

# 80. Worker crash

```text
Worker
 ↓
heartbeat lost
 ↓
lease expires
 ↓
job requeued
 ↓
another worker
```

---

# 81. Database unavailable

```text
API
 ↓
health check
 ↓
DEGRADED
```

No destructive automatic recovery.

Operations AI diagnoses.

---

# 82. User Permission Example

Admin configures:

```text
User: Rahul

Dashboard       ✓
APIHunter       ✓
Repository      ✓
AI Analysis     ✓
Findings        ✓

Credential reveal    ✗
Credential export    ✗

Security Center      ✓
Create scan          ✗

Workers              ✗
System settings      ✗
Users                ✗
```

The frontend hides unavailable features.

The API independently denies unauthorized requests.

---

# 83. Admin Dashboard Controls

Admin can globally control:

```text
Automatic AI investigation
Automatic website scanning
Email alerts
Telegram alerts
AI provider pool
Worker concurrency
Repository analysis
Security Center
Burp agents
```

---

# 84. Build Order

Do **not** build everything simultaneously.

### Phase 1 — Foundation (🔒 LOCKED)

```text
Platform DB
Authentication
Users
Permissions
Audit
Health
API
Frontend shell
```

### Phase 2 — APIHunter (🔒 LOCKED)

```text
APIHunter adapter
DB connection
sync
import
dashboard
```

### Phase 3 — Jobs (🔒 LOCKED)

```text
PostgreSQL queue
worker
leases
heartbeat
checkpoint
retry
```

### Phase 4 — Repository Intelligence (🔒 LOCKED)

```text
repository acquisition
snapshot
indexing
candidate detection
credential validation
AI investigation
```

### Phase 5 — AI Gateway (🔒 LOCKED)

```text
provider adapters
provider pool
fallback
cost tracking
prompt versioning
structured output
```

### Phase 6 — Security Findings & Graph Intelligence (🔒 LOCKED)

```text
finding model
evidence
history
risk engine
graph intelligence
dashboard
```

### Phase 7 — Automated Security Response & Remediation (🔒 LOCKED)

```text
remediation action domain
deterministic recommendation engine
response policy engine
approval & authorization workflow
remediation execution engine
post-remediation verification engine
remediation center UI & API
```

### Phase 8 — BugHunter

```text
adapter
worker
result normalization
finding integration
```

### Phase 9 — Burp

```text
local agent
secure connection
capability registration
job dispatch
evidence upload
```

### Phase 10 — Operations AI

```text
logs
metrics
traces
health
incident engine
AI diagnosis
```

### Phase 11 — Production hardening

```text
security
rate limiting
backup
recovery
load tests
adapter contract tests
deployment
```

---

# 85. Milestones

### M1 — Platform boots (🔒 LOCKED)
Login, Admin, User, Permission, DB migrations, Health, Audit.

### M2 — APIHunter connected (🔒 LOCKED)
Connection string, APIHunter import, Valid/ValidNoCredits detection, RepoReferences linked.

### M3 — Repository AI & Intelligence (🔒 LOCKED)
Repository acquisition, snapshot, index, candidate detection, validation, AI investigation, evidence.

### M4 — Multi-worker & Queue (🔒 LOCKED)
Durable queue, worker heartbeat, lease recovery, concurrency.

### M5 — AI Gateway & Health (🔒 LOCKED)
Provider adapters, router, cost tracking, operations copilot.

### M6 — Findings & Graph Intelligence (🔒 LOCKED)
Unified findings, graph builder, risk engine, lifecycle governance.

### M7 — Response & Remediation (🔒 LOCKED)
Remediation actions, recommendation engine, response policy, approval workflow, provider execution, verification, Remediation Center UI.

### M8 — BugHunter & Burp (PENDING)
BugHunter adapter, Burp agent.

### M9 — Production Hardening & Operations AI (PENDING)
Observability, rate limiting, operations copilot, final hardening.

---

# 86. Definition of Done

A feature is **not complete** until:

```text
✓ Domain model
✓ Application service
✓ API endpoint
✓ Authorization
✓ Audit event
✓ Database migration
✓ Unit tests
✓ Integration tests
✓ Failure handling
✓ Health reporting
✓ Structured logs
✓ Documentation
✓ Dashboard UI
```

---

# 87. How Multiple AI Agents Should Work Together

Assign ownership per phase/module.

Each agent must respect:

```text
Domain contracts
Application interfaces
API contracts
Database migrations
```

---

# 88. Agent Coordination Rule

Before modifying another module:

```text
Read its interface
 ↓
Read its tests
 ↓
Read its README
 ↓
Do not change contract without approval
```

---

# 89. Shared AI Agent Instructions

> You are implementing one module of APIHunter Security Intelligence Platform. Do not redesign existing architecture. Respect Domain → Application → Infrastructure dependency direction. External systems must be accessed through adapters. Never expose raw secrets through DTOs without explicit authorization. Never treat AI output as authoritative validation. All long-running work must use durable jobs/checkpoints. Every feature must have tests, structured logging, health reporting and failure handling. Read existing interfaces before modifying them. Do not modify the existing APIHunter application unless explicitly instructed.

---

# 90. Final Architecture

```text
                              ┌───────────────────────┐
                              │    NEXT.JS DASHBOARD  │
                              └───────────┬───────────┘
                                          │
                                          ▼
                              ┌───────────────────────┐
                              │    ASP.NET CORE API   │
                              │        .NET 10        │
                              └───────────┬───────────┘
                                          │
             ┌────────────────────────────┼────────────────────────────┐
             │                            │                            │
             ▼                            ▼                            ▼
      APIHUNTER ADAPTER              AI GATEWAY                SECURITY CENTER
             │                            │                            │
             ▼                            ▼                            ▼
      EXISTING APIHUNTER            AI PROVIDERS                WEB TARGETS
           DB                      ┌────┬────┬────┐                   │
                                   │    │    │    │                   ▼
                                 OpenAI DeepSeek Groq              Workers
                                                                      │
                                                        ┌─────────────┼────────────┐
                                                        ▼             ▼            ▼
                                                       JS          Browser      BugHunter
                                                     Analysis       Network       Adapter
                                                                                  │
                                                                                  ▼
                                                                                Burp*
                                                                                 
                                  ┌──────────────────────────────────────────────┐
                                  │             POSTGRESQL PLATFORM DB           │
                                  │                                               │
                                  │ Users / Permissions / Jobs / Findings        │
                                  │ Repositories / Credentials / AI / Health     │
                                  │ Security Center / Remediation / Audit        │
                                  └──────────────────────┬────────────────────────┘
                                                         │
                                                         ▼
                                                 DURABLE JOB QUEUE
                                                         │
                                      ┌──────────────────┼─────────────────┐
                                      ▼                  ▼                 ▼
                                   Worker 1            Worker 2         Worker N
                                      │                  │                 │
                                      └──────────────────┼─────────────────┘
                                                         │
                                                         ▼
                                               OBJECT STORAGE
                                                   IObjectStorage
                                                         │
                                                         ▼
                                                   Cloudflare R2
                                                         │
                                               later → MinIO/S3

                              * Burp/local agent is optional.
```

---

# 91. Most Important Architectural Invariants

1. APIHunter DB is external and read-only.
2. Platform DB is independent.
3. APIHunter access goes through an adapter.
4. External security tools go through adapters.
5. AI providers go through AI Gateway.
6. AI is never an authoritative validator.
7. Worker count is irrelevant to correctness.
8. Raw secrets are encrypted at rest and masked by default.
9. Every long-running job checkpoints progress.
10. All operations emit structured audit logs.
