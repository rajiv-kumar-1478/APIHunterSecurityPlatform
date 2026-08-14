# Finding Candidate Mapping & Canonical Fingerprinting

## `FindingCandidate` Record

Parsers convert scanner observations into standardized `FindingCandidate` records:

```csharp
public sealed record FindingCandidate(
    string ToolKey,
    string ToolVersion,
    FindingType FindingType,
    string Title,
    string? Description,
    string RawSeverity,
    string TargetUrl,
    string? CweId,
    string? EndpointPath,
    string? HttpMethod,
    string? ParameterName,
    string RuleOrTemplateId,
    string RawEvidenceJson,
    DateTime ObservedAtUtc
);
```

---

## Authority & Ingestion Flow

```text
FindingCandidate (Emitted by Parser)
          │
          ▼
   EvidenceSanitizer
          │
          ├── 1. Redact Authorization / Cookie headers
          ├── 2. Redact cleartext tokens (AKIA..., ghp_..., eyJ...)
          └── 3. Bounded JSON encoding (16 KiB ceiling)
          │
          ▼
FindingFingerprintService
          │
          ▼
Canonical v1 SHA-256 Digest:
SHA256("{FindingType}:{NormalizedTargetUrl}:{NormalizedEndpointPath}:{HttpMethod}:{ParameterName}:{RuleOrTemplateId}")
          │
          ▼
Phase 8 Finding Ingestion Engine
(Authoritative Deduplication, Status Transition, SLA Tracking)
```

---

## Static vs. Active Finding Classification

- **Static Observations (SAST, AST, Recon)**:
  - Must map to `FindingType.ProductionServiceExposed` with the specific `RuleOrTemplateId` (e.g. `cwe-89-sql-injection`, `dom-xss-potential`).
  - Represents a code-level or attack-surface discovery; never claims active confirmed exploitability by itself.

- **Active Dynamic Verification (DAST, BugHunter, Nuclei)**:
  - When actively verified against a target with reproducible proof-of-concept HTTP traffic, maps to specific finding types (`SqlInjection`, `ServerSideRequestForgery`, `AuthenticationBypass`).
