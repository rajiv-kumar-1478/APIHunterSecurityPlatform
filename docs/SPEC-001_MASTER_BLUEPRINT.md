# SPEC-001 — APIHunter Security Intelligence Platform — Implementation Blueprint

This is the **master implementation blueprint** I would give to multiple AI coding agents/contractors. The key rule is that all agents work against the same contracts and boundaries; no agent should redesign another module independently.

I recommend building the new platform on **.NET 10 + EF Core 10**, while leaving the existing APIHunter application untouched initially. .NET 10 is currently the LTS release supported through November 2028, while your existing APIHunter is on .NET 9, which remains supported until November 2026.

---

# 1. System Goal

Build a separate web-based security intelligence platform around the existing APIHunter system.

The platform must provide:

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

Every AI coding agent must follow these rules.

### Rule 1 — Never modify APIHunter directly for dashboard functionality

The existing APIHunter database is an external source.

```text
New Platform
     │
     ▼
APIHunter Adapter
     │
     ▼
Existing APIHunter DB
```

The APIHunter DB connection is supplied by configuration.

Use a **read-only DB account** wherever possible.

---

### Rule 2 — Platform has its own database

```text
APIHunter DB
     ≠
Platform DB
```

Platform DB contains:

* users
* permissions
* imported APIHunter intelligence
* repository investigations
* credential candidates
* validation results
* websites
* scans
* findings
* AI runs
* workers
* jobs
* health
* notifications
* audit logs

---

### Rule 3 — External tools always use adapters

```text
IApiHunterSource
IAiProvider
ISecurityScanner
IBurpAgent
IObjectStorage
INotificationProvider
IRepositoryProvider
```

Never call third-party libraries directly from business logic.

---

### Rule 4 — AI never becomes the source of truth

These are different:

```text
AI hypothesis
Credential candidate
Credential validation
Security finding
Confirmed vulnerability
```

Never collapse them into one status.

---

### Rule 5 — Worker count is irrelevant to correctness

The system must work with:

```text
1 worker
5 workers
50 workers
```

without code changes.

---

### Rule 6 — No long-running state in worker RAM

Every long-running job must checkpoint progress to PostgreSQL/object storage.

Worker restart must be recoverable.

---

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
| Cache            | Optional later                                                           |
| Object storage   | S3-compatible abstraction → Cloudflare R2 initially                      |
| Frontend         | Next.js/React                                                            |
| API              | REST/OpenAPI                                                             |
| Authentication   | ASP.NET Core Identity + secure cookie/session or OIDC-ready architecture |
| Logging          | `ILogger` + OpenTelemetry                                                |
| Metrics          | OpenTelemetry                                                            |
| Tracing          | OpenTelemetry                                                            |
| AI               | Provider-independent AI Gateway                                          |
| Repository       | GitHub/API adapters                                                      |
| Website browser  | Playwright-based worker                                                  |
| Security scanner | BugHunter adapter                                                        |
| Burp             | Optional local agent                                                     |
| Email            | Provider adapter                                                         |
| Telegram         | Existing integration adapter                                             |

Cloudflare R2 currently exposes an S3-compatible API, making it suitable for the storage abstraction and later migration to MinIO/S3-compatible infrastructure.

.NET's current observability stack supports logs, metrics and distributed traces through OpenTelemetry, which fits the platform-wide health/debugging requirement.

ASP.NET Core 10 also provides built-in health checks and rate-limiting middleware.

---

# 4. Repository Structure

Create a new repository:

```text
APIHunterSecurityPlatform/
│
├── src/
│   │
│   ├── Platform.Api/
│   │   ├── Controllers/
│   │   ├── Endpoints/
│   │   ├── Middleware/
│   │   ├── Authorization/
│   │   └── Program.cs
│   │
│   ├── Platform.Application/
│   │   ├── Common/
│   │   ├── Users/
│   │   ├── Permissions/
│   │   ├── APIHunter/
│   │   ├── Repositories/
│   │   ├── Credentials/
│   │   ├── AI/
│   │   ├── Security/
│   │   ├── Findings/
│   │   ├── Jobs/
│   │   ├── Agents/
│   │   ├── Health/
│   │   └── Notifications/
│   │
│   ├── Platform.Domain/
│   │   ├── Entities/
│   │   ├── Enums/
│   │   ├── ValueObjects/
│   │   ├── Events/
│   │   └── Contracts/
│   │
│   ├── Platform.Infrastructure/
│   │   ├── Persistence/
│   │   ├── Security/
│   │   ├── Storage/
│   │   ├── Queue/
│   │   ├── Observability/
│   │   └── Configuration/
│   │
│   ├── Platform.Worker/
│   │   ├── JobRunner/
│   │   ├── Handlers/
│   │   ├── Heartbeat/
│   │   └── Checkpointing/
│   │
│   ├── APIHunter.Adapter/
│   │   ├── Database/
│   │   ├── Mapping/
│   │   ├── Sync/
│   │   └── Compatibility/
│   │
│   ├── AI.Gateway/
│   │   ├── Providers/
│   │   ├── Routing/
│   │   ├── Prompts/
│   │   ├── Security/
│   │   ├── Operations/
│   │   └── StructuredOutput/
│   │
│   ├── Repository.Intelligence/
│   │   ├── Acquisition/
│   │   ├── Indexing/
│   │   ├── Detection/
│   │   ├── Analysis/
│   │   └── Investigation/
│   │
│   ├── SecurityCenter/
│   │   ├── Targets/
│   │   ├── Scheduling/
│   │   ├── Discovery/
│   │   ├── JavaScript/
│   │   ├── Network/
│   │   ├── Scanners/
│   │   └── Validation/
│   │
│   ├── BugHunter.Adapter/
│   │
│   ├── Burp.Agent/
│   │
│   └── Notifications/
│       ├── Email/
│       └── Telegram/
│
├── frontend/
│   └── dashboard/
│
├── tests/
│   ├── Unit/
│   ├── Integration/
│   ├── Contract/
│   └── EndToEnd/
│
├── deployment/
│   ├── docker/
│   ├── migrations/
│   └── environments/
│
├── docs/
│   ├── architecture/
│   ├── api/
│   ├── operations/
│   └── agents/
│
└── README.md
```

---

# 5. Dependency Direction

This must never be violated:

```text
Domain
   ↑
Application
   ↑
Infrastructure
   ↑
API / Worker / Adapters
```

External adapters depend inward.

Never:

```text
Domain → BugHunter
Domain → OpenAI
Domain → PostgreSQL
Domain → Burp
```

Instead:

```text
Application
     │
     ▼
Interface
     ▲
     │
Adapter
```

---

# 6. Core Domain Model

## User

```text
User
-----
Id
Email
Username
DisplayName
PasswordHash
IsAdmin
IsActive
CreatedAt
UpdatedAt
LastLoginAt
```

Only:

```text
ADMIN
USER
```

No hardcoded Analyst/Viewer roles.

---

# 7. Permission Model

### Permissions

```text
Permission
----------
Id
Code
Name
Category
Description
```

Examples:

```text
dashboard.view

apihunter.view
apihunter.search
apihunter.stop

repository.view
repository.investigate

credential.view
credential.view_validation
credential.view_ai
credential.reveal
credential.export

security.target.view
security.scan.view
security.scan.create
security.scan.stop
security.finding.view
security.finding.validate

ai.view
ai.manage

worker.view
worker.manage

system.health.view

notification.view
notification.manage

user.manage
permission.manage

audit.view
```

### UserPermission

```text
UserPermission
--------------
UserId
PermissionId
Enabled
```

---

# 8. Field-Level Permissions

Admin must be able to decide what information a user sees.

```text
FieldPermission
---------------
Id
PermissionId
ResourceType
FieldName
Action
```

Examples:

```text
credential.raw_value
credential.validation_response
credential.code_context
finding.evidence
finding.network_data
repository.source
```

The backend evaluates this.

Frontend hiding is **not security**.

---

# 9. Platform Database

Recommended major tables:

```text
users
permissions
user_permissions
field_permissions

api_hunter_sources
api_hunter_imports

repositories
repository_references
repository_snapshots
repository_investigations

credential_candidates
credentials
credential_validations
credential_assessments
credential_relationships

security_targets
web_assets
web_endpoints
network_observations
scan_schedules
scan_sessions

findings
finding_evidence
finding_validations
finding_history

jobs
job_attempts
job_checkpoints
workers
worker_capabilities

ai_providers
ai_provider_credentials
ai_models
ai_runs
ai_observations
ai_prompts

health_components
health_events
incidents

notification_rules
notification_deliveries

audit_events
```

---

# 10. APIHunter Adapter

The adapter exposes:

```text
IApiHunterSource
```

Methods conceptually:

```text
GetApiKeysAsync()
GetApiKeyAsync(sourceId)
GetRepoReferencesAsync(sourceId)
GetServerCredentialsAsync()
GetSearchInformationAsync()
GetChangesSinceAsync(cursor)
CheckCompatibilityAsync()
```

The adapter knows APIHunter's schema.

Nothing else does.

---

# 11. APIHunter Sync

Flow:

```text
APIHunter DB
    ↓
Change detector
    ↓
APIHunter adapter
    ↓
Import queue
    ↓
Platform DB
```

Maintain:

```text
api_hunter_imports
------------------
Id
SourceTable
SourceRecordId
SourceVersion
SourceHash
ImportedAt
LastSeenAt
SyncStatus
```

Use a source hash so repeated records are cheap to detect.

---

# 12. APIHunter Status Mapping

Never hardcode integer meanings throughout the application.

Create:

```text
IApiHunterStatusMapper
```

Then map:

```text
APIHunter
Valid
      ↓
Platform
VALID
```

```text
APIHunter
ValidNoCredits
      ↓
Platform
VALID_NO_CREDIT
```

If APIHunter changes later, modify the adapter.

---

# 13. Repository Investigation Trigger

Automatic trigger:

```text
APIHunter import
       ↓
Status = VALID
       OR
Status = VALID_NO_CREDIT
       ↓
RepoReference exists?
       ↓
YES
       ↓
Repository investigation job
```

Admin setting:

```text
Automatic AI Repository Investigation
ON / OFF
```

If OFF:

```text
APIHunter → imported
          → investigation NOT queued
```

---

# 14. Repository Deduplication

If 50 credentials point to the same repository:

```text
50 credentials
      ↓
1 repository
      ↓
1 snapshot
      ↓
1 shared repository index
      ↓
shared investigation
```

Credential-specific analysis happens afterward.

Use:

```text
RepositoryId
CommitSha
AnalysisVersion
```

as the investigation identity.

---

# 15. Repository Acquisition

For public repositories:

```text
Repository
   ↓
Acquire
   ↓
Snapshot
   ↓
SHA-256
   ↓
Object Storage
```

For private repositories without authorization:

```text
ACCESS_REQUIRED
```

Do not bypass private access.

Later:

```text
GitHub App / authorized token
```

can be plugged in through:

```text
IRepositoryProvider
```

---

# 16. Repository Index

Do not send the whole repository directly to an AI model.

First build:

```text
Repository Index
----------------
files
directories
languages
file sizes
git metadata
dependencies
config files
CI/CD
IaC
API definitions
documentation
source references
```

Classify files:

```text
HIGH_VALUE
MEDIUM_VALUE
LOW_VALUE
GENERATED
BINARY
IGNORED
```

---

# 17. Credential Detection

Detection sources:

```text
APIHunter
Pattern detectors
Configuration parser
Environment parser
Secret detectors
AI suggestions
```

But:

```text
Pattern match
      ≠
Credential
```

Candidate:

```text
credential_candidates
---------------------
Id
RepositoryId
InvestigationId
Type
Provider
Fingerprint
EncryptedValueRef
FilePath
LineStart
LineEnd
DetectionMethod
DetectionConfidence
Status
CreatedAt
```

---

# 18. Credential State Machine

```text
CANDIDATE
   ↓
CONTEXT_ANALYSIS
   ↓
VALIDATION_PENDING
   ↓
VALIDATING
   ├── VALID
   ├── VALID_NO_CREDIT
   ├── INVALID
   ├── UNKNOWN
   └── UNSUPPORTED
```

For unsupported credentials:

```text
Potential Credential — Unverified
```

Never falsely call it valid.

---

# 19. Credential Validation

Interface:

```text
ICredentialValidator
--------------------
CanHandle(candidate)
ValidateAsync(candidate, context)
```

Result:

```text
CredentialValidationResult
--------------------------
Status
Confidence
ValidatorType
ValidatorVersion
EvidenceReference
ErrorCode
StartedAt
CompletedAt
```

API credentials should reuse APIHunter provider validation wherever appropriate.

Database/server/cloud validators should perform only safe, non-destructive validation against authorized targets.

---

# 20. AI Repository Analysis

AI receives structured context:

```text
Repository metadata
Relevant files
Relevant configuration
Dependency information
CI/CD information
Infrastructure information
Credential candidates
Relationships
Validation results
```

AI returns structured output:

```json
{
  "observations": [],
  "relationships": [],
  "risk": {},
  "recommended_validations": [],
  "summary": ""
}
```

Do not parse arbitrary prose.

---

# 21. AI Security Investigation

Pipeline:

```text
Repository
    ↓
Index
    ↓
Deterministic Detection
    ↓
Candidate Context Analysis
    ↓
Credential Validation
    ↓
AI Relationship Analysis
    ↓
Risk Analysis
    ↓
Finding Generation
```

AI should investigate:

```text
API credentials
Cloud credentials
Database credentials
Server credentials
CI/CD credentials
Infrastructure secrets
Authentication configuration
Authorization configuration
Production indicators
Sensitive endpoints
Credential relationships
```

---

# 22. AI Evidence Rule

Every important AI observation requires:

```text
Evidence
+
File
+
Line/range where possible
+
Snapshot/commit
```

AI cannot produce:

```text
"Critical vulnerability"
```

without an evidence reference.

---

# 23. AI Provider Gateway

Never:

```text
RepositoryService → OpenAI SDK
```

Instead:

```text
RepositoryService
       ↓
IAiGateway
       ↓
AI Provider Router
       ↓
Authorized Provider
```

Providers:

```text
OpenAI
DeepSeek
Groq
Anthropic
Future providers
```

Only **Admin-authorized credentials** can be placed into the AI provider pool.

Discovered public credentials must never automatically become platform AI credentials.

---

# 24. AI Provider Database

```text
ai_provider_credentials
-----------------------
Id
Provider
Label
EncryptedApiKey
Fingerprint
Enabled
Priority
DailyLimit
MonthlyLimit
AllowedWorkloads
LastHealthCheck
FailureCount
CreatedAt
UpdatedAt
```

Automatic selection:

```text
AI job
 ↓
Eligible providers
 ↓
Healthy?
 ↓
Quota?
 ↓
Model capability?
 ↓
Priority
 ↓
Execute
```

Fallback:

```text
OpenAI failure
 ↓
DeepSeek
 ↓
Groq
```

---

# 25. AI Operations Copilot

Separate from security AI.

Inputs:

```text
application logs
worker logs
adapter logs
health checks
job failures
exceptions
package versions
deployment versions
AI failures
database failures
queue failures
```

Output:

```text
HEALTHY
DEGRADED
BROKEN
OFFLINE
UNKNOWN
```

AI can say:

```text
BugHunter Adapter DEGRADED

Likely cause:
Package/API incompatibility.

Evidence:
Adapter failures started after deployment X.

Affected:
Website jobs.

Not affected:
APIHunter.
Repository intelligence.
Database.
```

AI should recommend changes, not silently modify production dependencies.

---

# 26. Operations Observability

Every component emits:

```text
trace_id
correlation_id
service
component
event_code
severity
job_id
worker_id
timestamp
message
exception
metadata
```

Use OpenTelemetry for logs/metrics/tracing.

---

# 27. Health Checks

Every major component exposes health.

```text
API
Database
Queue
Object Storage
APIHunter
AI providers
Repository provider
BugHunter
Email
Telegram
Workers
Burp agents
```

Health states:

```text
HEALTHY
DEGRADED
UNHEALTHY
OFFLINE
UNKNOWN
```

---

# 28. Durable Job System

For your free-hosting situation, I recommend **PostgreSQL as the durable queue initially**, instead of making Redis mandatory.

Why?

You already need PostgreSQL.

Therefore:

```text
1 PostgreSQL
+
1 API
+
1 Worker
```

is enough for MVP.

Later Redis/RabbitMQ can be introduced behind:

```text
IJobQueue
```

---

# 29. Job Table

```text
jobs
----
Id
Type
Status
Priority

RepositoryId
TargetId
InvestigationId

PayloadJson

AttemptCount
MaxAttempts

LeaseOwner
LeaseExpiresAt

ScheduledAt
StartedAt
CompletedAt

CreatedAt
UpdatedAt
```

States:

```text
QUEUED
RUNNING
PAUSED
RETRYING
COMPLETED
FAILED
CANCELLED
```

---

# 30. Worker Claiming

Use PostgreSQL row locking/lease semantics.

Conceptually:

```text
BEGIN

SELECT job
FROM jobs
WHERE status = QUEUED
  AND scheduled_at <= now()
ORDER BY priority DESC, created_at
FOR UPDATE SKIP LOCKED
LIMIT 1;

UPDATE job
SET status = RUNNING,
    lease_owner = worker_id,
    lease_expires_at = ...
    
COMMIT
```

This allows:

```text
Worker A
Worker B
Worker C
```

to safely compete for jobs.

---

# 31. Worker Heartbeat

Every worker:

```text
register
 ↓
heartbeat
 ↓
claim job
 ↓
checkpoint
 ↓
heartbeat
 ↓
complete
```

Worker table:

```text
workers
-------
Id
Name
Version
Status
CapabilitiesJson
LastHeartbeatAt
CurrentJobId
RegisteredAt
```

---

# 32. Failed Worker Recovery

If:

```text
LeaseExpiresAt < NOW()
```

then:

```text
RUNNING
 ↓
worker lost
 ↓
REQUEUE
 ↓
another worker
```

No manual repair.

---

# 33. Checkpointing

Long jobs use:

```text
job_checkpoints
---------------
Id
JobId
CheckpointType
Sequence
StateJson
ArtifactReference
CreatedAt
```

Repository example:

```text
files indexed = 3000
analysis batch = 8
last file = src/x/y.cs
```

Worker restart:

```text
checkpoint
   ↓
resume
```

---

# 34. Website Security Center

Target:

```text
security_targets
----------------
Id
Name
BaseUrl
TargetType
Enabled
MonitoringEnabled
ScanInterval
LastScanAt
NextScanAt
CreatedAt
UpdatedAt
```

Only targets explicitly configured in your platform should enter active scanning workflows.

---

# 35. Website Scan

```text
Target
 ↓
Scheduler
 ↓
Scan session
 ↓
Passive discovery
 ↓
JS discovery
 ↓
Endpoint discovery
 ↓
Browser/network observation
 ↓
AI investigation
 ↓
Candidate finding
 ↓
Validation
 ↓
Finding
```

The scanner should use conservative rate limits and respect authorization/scope.

---

# 36. JavaScript Intelligence

For each JS asset:

```text
download
 ↓
hash
 ↓
compare previous hash
 ↓
extract endpoints/configuration/candidates
 ↓
store structured intelligence
```

Tables:

```text
web_assets
web_endpoints
network_observations
```

Large artifacts go to object storage.

---

# 37. BugHunter Adapter

Interface:

```text
ISecurityScanner
----------------
GetCapabilities()
StartAsync(scanContext)
GetStatusAsync(jobId)
CancelAsync(jobId)
CollectResultsAsync(jobId)
HealthCheckAsync()
```

Implementation:

```text
BugHunterAdapter
```

Do not embed BugHunter implementation throughout the application.

If its package/API changes:

```text
BugHunterAdapter
```

is updated.

---

# 38. Burp Agent

Burp is optional.

```text
Cloud
 ↓
Job requiring Burp
 ↓
Agent queue
 ↓
Local Burp Agent
 ↓
Burp/MCP
 ↓
Evidence
 ↓
Cloud
```

The local agent uses an outbound secure connection.

Do **not** expose Burp's control interface directly to the public internet.

If the agent is offline:

```text
Job = WAITING_FOR_CAPABLE_AGENT
```

The rest of the platform continues operating.

---

# 39. Security Findings

One unified finding model:

```text
findings
--------
Id
SourceType
SourceId

RepositoryId
TargetId

FindingType
Severity
Confidence
Status

Title
Summary

FirstSeenAt
LastSeenAt
ResolvedAt

CreatedAt
UpdatedAt
```

Sources can include:

```text
APIHUNTER
REPOSITORY_AI
WEBSITE_SCANNER
BUGHUNTER
BURP
MANUAL
```

---

# 40. Finding Lifecycle

```text
DISCOVERED
 ↓
INVESTIGATING
 ↓
NEEDS_VALIDATION
 ↓
CONFIRMED
```

Alternative:

```text
FALSE_POSITIVE
```

or:

```text
RESOLVED
```

Never allow:

```text
AI says SQL injection
 ↓
CONFIRMED
```

There must be evidence/validation.

---

# 41. Evidence Storage

Database stores metadata:

```text
finding_evidence
----------------
Id
FindingId
EvidenceType
StorageKey
SHA256
MetadataJson
CreatedAt
```

Object storage stores:

```text
repository archives
screenshots
HAR/network artifacts
large logs
scanner output
AI evidence packages
```

---

# 42. Object Storage Interface

```text
IObjectStorage
---------------

PutAsync()
GetAsync()
DeleteAsync()
ExistsAsync()
GetMetadataAsync()
CreateDownloadUrlAsync()
```

Implementation:

```text
R2ObjectStorage
```

Later:

```text
MinioObjectStorage
S3ObjectStorage
```

No application-level changes.

---

# 43. Notifications

Interface:

```text
INotificationProvider
```

Implement:

```text
EmailNotificationProvider
TelegramNotificationProvider
```

Notification rules:

```text
notification_rules
------------------
Id
EventType
SeverityThreshold
Channel
Enabled
Recipient
```

Do not send raw credentials through email/Telegram.

---

# 44. Dashboard Structure

Main navigation:

```text
Overview

APIHunter
 ├── Overview
 ├── Searches
 ├── Valid
 ├── ValidNoCredits
 ├── Credentials
 └── Sync

Repository Intelligence
 ├── Repositories
 ├── Investigations
 ├── Secrets
 └── Relationships

Security Center
 ├── Overview
 ├── Websites
 ├── Assets
 ├── Endpoints
 ├── Scans
 └── Findings

Findings

AI
 ├── Investigations
 ├── Providers
 ├── Usage
 └── Operations AI

Workers
 ├── Workers
 ├── Agents
 └── Jobs

System Health

Notifications

Users

Permissions

Audit
```

---

# 45. Dashboard UX

Always:

```text
Summary
   ↓
Detail
   ↓
Evidence
   ↓
History
```

Never expose huge raw datasets on the homepage.

---

# 46. Main Overview

Display:

```text
Valid credentials
ValidNoCredits
Potential credentials
Critical findings
High findings
Monitored websites
Active scans
Running jobs
Workers online
AI health
System health
```

Example:

```text
VALID CREDENTIALS       128
VALID NO CREDIT          41
POTENTIAL                76

CRITICAL FINDINGS         4
HIGH FINDINGS            12

WEBSITES                 23
ACTIVE SCANS              7
WORKERS                   3

SYSTEM HEALTH          HEALTHY
```

---

# 47. Credential Detail

```text
Credential
 ├── Summary
 ├── Validation
 ├── Repository
 ├── Related Secrets
 ├── AI Investigation
 ├── Evidence
 └── History
```

Default:

```text
••••••••••••••••9f31
```

Raw reveal requires:

```text
credential.reveal
```

and must generate an audit event.

---

# 48. Repository Detail

```text
Repository
 ├── Overview
 ├── Risk Summary
 ├── Credentials
 ├── AI Observations
 ├── Relationships
 ├── Findings
 ├── Files
 ├── Commits
 └── Investigation History
```

---

# 49. Website Detail

```text
Website
 ├── Overview
 ├── Scan Status
 ├── Assets
 ├── JavaScript
 ├── Endpoints
 ├── Network
 ├── Findings
 ├── AI Investigation
 └── Scan History
```

---

# 50. System Health Dashboard

Example:

```text
API                    🟢
Platform DB            🟢
APIHunter              🟢
Queue                  🟢
Object Storage         🟢
AI Provider Pool       🟢
Repository Workers     🟢
BugHunter              🟢
Email                  🟢
Telegram               🟢
Burp Agent             ⚪ OFFLINE
```

AI diagnosis appears only when something is degraded/broken.

---

# 51. AI Operations Incident

```text
Incident #1024

Component:
BugHunter Adapter

Status:
DEGRADED

Started:
12:31

Likely Cause:
Package/API incompatibility

Evidence:
deployment
package version
stack trace
failed jobs

Impact:
17 website jobs queued

Recommendation:
Update BugHunter adapter compatibility layer
```

---

# 52. Security

Mandatory:

```text
HTTPS
secure cookies
CSRF protection where applicable
password hashing
session expiration
rate limiting
audit logging
encrypted secrets
secret masking
least privilege
read-only APIHunter DB
```

---

# 53. Secret Encryption

Never:

```text
encrypted = false
```

for platform-managed credentials.

Use:

```text
EncryptedSecret
-------------
Ciphertext
KeyVersion
Nonce/IV
Algorithm
CreatedAt
```

The encryption master key lives outside PostgreSQL, supplied through deployment secret management.

---

# 54. Audit

Audit:

```text
login
logout
permission_change
user_create
user_disable

secret_reveal
secret_export

scan_start
scan_stop

finding_change
finding_validation

ai_provider_add
ai_provider_disable

agent_register

system_setting_change
```

---

# 55. API Design

Use versioned APIs:

```text
/api/v1/auth
/api/v1/dashboard
/api/v1/apihunter
/api/v1/repositories
/api/v1/credentials
/api/v1/investigations
/api/v1/security
/api/v1/findings
/api/v1/jobs
/api/v1/workers
/api/v1/ai
/api/v1/health
/api/v1/users
/api/v1/permissions
/api/v1/audit
```

Every endpoint must pass:

```text
Authentication
 ↓
Permission
 ↓
Resource authorization
 ↓
Field authorization
 ↓
Data access
```

---

# 56. Example APIHunter API

```text
GET /api/v1/apihunter/credentials
GET /api/v1/apihunter/credentials/{id}

GET /api/v1/apihunter/repositories

POST /api/v1/apihunter/sync

GET /api/v1/apihunter/sync/status
```

---

# 57. Example investigation API

```text
GET /api/v1/repositories/{id}

GET /api/v1/repositories/{id}/investigations

POST /api/v1/repositories/{id}/investigations

GET /api/v1/investigations/{id}

GET /api/v1/investigations/{id}/observations
```

Automatic investigation jobs should normally be created by the synchronization pipeline rather than by clients.

---

# 58. Example Security Center API

```text
GET /api/v1/security/targets

POST /api/v1/security/targets

PATCH /api/v1/security/targets/{id}

POST /api/v1/security/targets/{id}/scans

GET /api/v1/security/scans/{id}

GET /api/v1/security/targets/{id}/findings
```

Active scanning functionality must remain limited to targets configured for the platform and subject to the platform's authorization policy.

---

# 59. API Contract Rule

Every API response should use DTOs.

Never expose EF entities directly.

```text
EF Entity
   ↓
Application DTO
   ↓
Authorization filtering
   ↓
API Response
```

This is especially important for secrets.

---

# 60. Worker Handlers

Worker should use handlers:

```text
IJobHandler
```

Implement:

```text
ApiHunterSyncHandler

RepositoryAcquireHandler
RepositoryIndexHandler
RepositorySecretDetectionHandler
RepositoryAiAnalysisHandler
CredentialValidationHandler

WebsiteDiscoveryHandler
JavascriptAnalysisHandler
NetworkAnalysisHandler
SecurityInvestigationHandler

FindingValidationHandler

AiHealthCheckHandler
OperationsAnalysisHandler

NotificationHandler
```

---

# 61. Worker Registration

Every worker announces:

```text
worker_id
version
capabilities
max_concurrency
memory_limit
```

Capabilities:

```text
repository
ai
website
browser
bughunter
burp
```

Scheduler matches jobs to capabilities.

---

# 62. One Worker MVP

Initial deployment:

```text
Frontend
    │
Backend
    │
PostgreSQL
    │
Worker-01
    │
R2
```

That is enough.

---

# 63. Multi-worker deployment

Later:

```text
Backend
   │
PostgreSQL Queue
   │
 ┌─┼───────────────┐
 ▼ ▼               ▼
W1 W2              W3
```

No business logic changes.

---

# 64. Free Hosting Strategy

Do not try to combine CPUs physically.

Instead:

```text
Free Host 1 → Worker 1
Free Host 2 → Worker 2
Free Host 3 → Worker 3
```

All pull from the same queue.

One worker still works.

Multiple workers increase throughput.

---

# 65. Deployment Configuration

Never hardcode:

```text
API keys
database passwords
JWT secrets
R2 credentials
AI provider keys
GitHub tokens
```

Use environment variables/secrets.

Example:

```text
PLATFORM_DATABASE_URL=

APIHUNTER_DATABASE_URL=

R2_ENDPOINT=
R2_ACCESS_KEY=
R2_SECRET_KEY=
R2_BUCKET=

AUTH_ENCRYPTION_KEY=

AI_PROVIDER_CONFIGURATION=

WORKER_CAPABILITIES=
```

---

# 66. Migration Strategy

Platform DB uses EF migrations:

```text
Migration 001
Core users

Migration 002
Permissions

Migration 003
Repositories

Migration 004
Credentials

Migration 005
Investigations

Migration 006
Security Center

Migration 007
Jobs

Migration 008
AI

...
```

Never manually modify production schema without a migration.

---

# 67. Testing Strategy

Every module needs:

### Unit tests

```text
permission evaluation
status mapping
job transitions
risk scoring
credential classification
AI response parsing
```

### Integration tests

```text
PostgreSQL
APIHunter adapter
R2 adapter
AI provider adapter
queue
worker
```

### Contract tests

```text
BugHunter adapter
APIHunter schema
AI providers
Burp agent
```

### End-to-end

```text
APIHunter import
 ↓
repository investigation
 ↓
credential candidate
 ↓
validation
 ↓
finding
 ↓
dashboard
 ↓
notification
```

---

# 68. Adapter Contract Testing

This is critical for future package updates.

Every adapter gets:

```text
CompatibilityTest
HealthTest
HappyPathTest
FailureTest
TimeoutTest
VersionTest
```

When a package is upgraded:

```text
CI
 ↓
adapter tests
 ↓
contract tests
 ↓
integration tests
 ↓
deployment
```

---

# 69. AI Prompt Versioning

Never keep prompts as random strings inside C# code.

Use:

```text
Prompts/
  repository/
    v1/
    v2/
    v3/

  credential/
    v1/
    v2/

  operations/
    v1/
    v2/
```

Every AI run stores:

```text
prompt_version
model
provider
```

So results are reproducible/auditable.

---

# 70. AI Hallucination Protection

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
