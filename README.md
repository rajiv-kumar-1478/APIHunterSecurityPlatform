# APIHunter Security Intelligence Platform

> **Enterprise-Grade API & Application Security Platform** | .NET 10 + EF Core 10 + Next.js 16 (Turbopack) + PostgreSQL | Capability-Driven Scanner Orchestration & Immutable Provenance

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![.NET Core](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16.3.0-black.svg)](https://nextjs.org/)
[![Tests](https://img.shields.io/badge/Unit%20Tests-670%20passed-brightgreen.svg)]()
[![Integration Tests](https://img.shields.io/badge/Integration%20Tests-83%20passed-brightgreen.svg)]()

---

## Architecture Overview

```text
                               APIHunter Security Platform
                                            │
    ┌───────────────────────────────────────┴───────────────────────────────────────┐
    ▼                                                                               ▼
Backend Services (.NET 10)                                              Frontend Dashboard (Next.js 16)
  ├── Platform.Domain (Entities, Enums, Contracts)                        ├── Security Intelligence Hub
  ├── Platform.Application (Services, DTOs, Security Rules)               ├── Findings & Remediation Center
  ├── Platform.Infrastructure (EF Core, PostgreSQL, Sandboxes)             ├── Automated Scan Campaigns
  ├── Platform.Api (REST APIs & Minimal Endpoints)                        ├── Scanner Registry & Provenance
  └── Platform.Worker (Background Workers & Schedulers)                   └── Tenant Access & Permission Controls
```

---

## Platform Capability & Phase Progression

### 1. Core Security & Remediation (Phases 1 – 7)
- **Authentication & Authorization**: Cookie sessions (`__ap_session`), CSRF tokens (`X-CSRF-TOKEN`), granular field-level permissions, tenant isolation, and administrative audit logging.
- **Credential & Secret Lifecycle**: Secure credential detection, entropy analysis, and masked visualization with strict permission gates (`credential.reveal`).
- **Remediation Engine**: Automated Jira/GitHub issue creation, SLA escalation policies, rollback webhooks, and manual override tracking.
- **AI Investigation**: Contextual threat intelligence and non-authoritative advisory enrichment.

### 2. Authoritative Finding Ingestion & Risk Scoring (Phase 8)
- **Multi-Layer Sanitization**: Strips Authorization headers, Bearer tokens, private keys, and session cookies from all scanner evidence.
- **Canonical v1 Fingerprinting**: Deterministic SHA-256 finding deduplication hashes across all scanners:
  ```text
  FindingFingerprint = SHA256($"{TenantId}:{TargetKind}:{NormalizedEndpoint}:{NormalizedMethod}:{NormalizedParam}:{CweId}")
  ```
- **Deterministic Risk Engine**: Weighted asset criticality scoring, CVSS mapping, and SLA calculation.

### 3. Automated Campaign Scheduler & Observability (Phases 9.1 – 9.3)
- **Cron-Driven Campaigns**: High-throughput distributed scheduling with database-backed optimistic concurrency gates.
- **Durable Concurrency**: Prevents redundant scans against target deployments and enforces tenant concurrency quotas.
- **Observability Hub**: Real-time throughput metrics, failure diagnostics, success rates, and audit logs.

### 4. Capability-Driven Scanner Architecture (SPEC-008.1 – 008.10)
- **Universal Plugin Contract (`IScanToolAdapter`)**: Integrates any security tool (`httpx`, `nuclei`, `subfinder`, `jsminer`, `bughunter`, `semgrep`, `trufflehog`, `zap`) without hardcoded scanner names.
- **Dynamic Scan Planning Engine (`IScanPlanningEngine`)**: Resolves target kinds, required capabilities, security profiles (`Standard`, `Deep`), and active tool health into a deterministic `ResolvedScanPlan` with a verifiable `PlanHash`.
- **Scanner-Independent Execution Engine (`IScanExecutionEngine`)**: Owns sandbox creation (`cap_drop = ALL`, read-only roots), per-tool timeout limits (300s), per-tool invocation accountability (`ScanToolInvocationRecord`), candidate ingestion, and granular status reporting (`Completed`, `CompletedWithToolFailures`, `Failed`).
- **Tamper-Evident Audit & Provenance Layer (`IScanPlanAuditService`)**: Cryptographically chains scan plan records with canonical hashing:
  ```text
  RecordHash = SHA256($"{ScanJobId}:{TenantId}:{PlanHash}:{RegistrySnapshotHash}:{Sequence}:{PlannerVersion}:{PreviousAuditHash}")
  ```
- **Dual-Defense AI Advisory Boundary (`JsAiEnrichmentService` & `AiEvidenceProjector`)**: Completely decoupled from authoritative finding ingestion. AI advisory failures fail-open and never alter scan results, findings, or severity.
- **Decoupled Frontend UI Read Models**: Frontend consumes platform canonical DTOs only; raw scanner JSON/XML never crosses the adapter boundary.

---

## System Execution Flow

```text
Scan Request / Scheduled Campaign
               │
               ▼
      IScanPlanningEngine (SPEC-008.8)
               │
               ├── Target Asset Kind (WebEndpoint / SourceRepo / JS)
               ├── Required Capabilities (e.g. sast.scan, http.probe)
               └── Security Profile (Standard / Deep)
               │
               ▼
        ResolvedScanPlan (PlanHash)
               │
               ▼
      IScanExecutionEngine (SPEC-008.10)
               │
       ┌───────┼────────────────────────┐
       ▼       ▼                        ▼
     httpx   Semgrep                 Nuclei
       │       │                        │
       └───────┼────────────────────────┘
               ▼
    IScannerRuntimeSandbox (cap_drop=ALL, RO root)
               │
               ▼
     Tool Output Parsers (Bounded Streaming)
               │
               ▼
       FindingCandidate
               │
               ▼
       EvidenceSanitizer (Redacts Secrets)
               │
               ▼
   FindingFingerprintService (Canonical v1 Digest)
               │
               ▼
  ScanFindingIngestionEngine (Phase 8 Database)
               │
               ├────────────────────────┬────────────────────────┐
               ▼                        ▼                        ▼
     GET .../findings/{id}    GET .../provenance      GET .../invocations
       (FindingDetailDto)  (ScanProvenanceResponse) (ScanJobExecutionSummaryDto)
```

---

## API Catalog

### Authentication & Tenant Security
```http
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{id}
GET    /api/v1/auth/csrf
```

### Scanner Management, Invocations & Provenance
```http
GET    /api/v1/security/scans/capabilities             # Capability taxonomy manifest
GET    /api/v1/security/scans/tools                    # Scanner registry health & OCI digests
GET    /api/v1/security/scans/providers                # Active provider configs
GET    /api/v1/security/scans/jobs                     # Scan jobs list (paginated)
GET    /api/v1/security/scans/jobs/{id}                # Job detail & coverage metrics
GET    /api/v1/security/scans/jobs/{id}/receipt        # Execution receipt
GET    /api/v1/security/scans/jobs/{id}/provenance     # Forensic provenance & PlanHash audit
GET    /api/v1/security/scans/jobs/{id}/invocations    # Ordered tool invocation timeline
POST   /api/v1/security/scans/jobs                     # Trigger new scan job
POST   /api/v1/security/scans/jobs/{id}/cancel         # Cancel running scan job
```

### Security Findings & AI Advisory
```http
GET    /api/v1/findings                                # List findings with filtering
GET    /api/v1/findings/{id}                           # Canonical finding detail & AI advisory
PATCH  /api/v1/findings/{id}/status                    # Update finding lifecycle state
```

### Scan Campaigns & Observability
```http
GET    /api/v1/campaigns                               # List scheduled campaigns
POST   /api/v1/campaigns                               # Create scan campaign
GET    /api/v1/campaigns/{id}                          # Campaign details
PUT    /api/v1/campaigns/{id}                          # Update campaign schedule
POST   /api/v1/campaigns/{id}/pause                    # Pause campaign
POST   /api/v1/campaigns/{id}/resume                   # Resume campaign
POST   /api/v1/campaigns/{id}/run-now                  # Trigger instant campaign execution
GET    /api/v1/campaigns/{id}/audit-logs               # Campaign execution audit logs
GET    /api/v1/campaigns/observability/health          # Tenant health & run statistics
GET    /api/v1/campaigns/observability/metrics         # Windowed execution metrics
```

---

## Scanner Developer Documentation

Comprehensive documentation for developing and onboarding new scanner adapters is located in [`docs/scanner-development/`](./docs/scanner-development/):

| Guide | Description |
|---|---|
| [`adapter-contract.md`](./docs/scanner-development/adapter-contract.md) | Universal `IScanToolAdapter` interface, lifecycle, and execution contracts. |
| [`manifest-and-provenance.md`](./docs/scanner-development/manifest-and-provenance.md) | `ScanToolManifest` rules, OCI registry digests, and provenance validation. |
| [`capability-taxonomy.md`](./docs/scanner-development/capability-taxonomy.md) | Platform capability taxonomy tags, target asset types, and execution phases. |
| [`output-parser-contract.md`](./docs/scanner-development/output-parser-contract.md) | Bounded streaming parser requirements, resource limits, and error resilience. |
| [`sandbox-requirements.md`](./docs/scanner-development/sandbox-requirements.md) | `IScannerRuntimeSandbox` execution, capability dropping, and network isolation. |
| [`finding-mapping.md`](./docs/scanner-development/finding-mapping.md) | Mapping tool findings to `FindingCandidate`, evidence redaction, and canonical v1 fingerprinting. |
| [`testing-requirements.md`](./docs/scanner-development/testing-requirements.md) | Golden fixtures, adversarial parsing, manifest validation, and plan determinism tests. |
| [`dashboard-integration.md`](./docs/scanner-development/dashboard-integration.md) | Frontend UI decoupled read models, provenance display, and boundary invariants. |
| [`adding-a-new-scanner.md`](./docs/scanner-development/adding-a-new-scanner.md) | Step-by-step developer checklist for onboarding a new scanner plugin. |

---

## Local Verification & Testing

### 1. Run Unit Tests (670 Tests)
```bash
dotnet test tests/Platform.UnitTests/
```

### 2. Run Integration Tests (83 Tests)
```bash
dotnet test tests/Platform.IntegrationTests/ --filter "FullyQualifiedName!~CampaignSchedulerRaceTests"
```

### 3. Build Frontend Dashboard
```bash
npm --prefix frontend/dashboard run build
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
