# Dashboard Integration & Canonical UI Read Models

## UI Decoupling Invariant

> **The APIHunter dashboard consumes platform-owned canonical read models only. Scanner-specific JSON, XML, or CLI output formats must NEVER cross the adapter/parser boundary into the frontend UI.**

This invariant guarantees that onboarding new tools (such as **OWASP ZAP**, **TruffleHog**, **Trivy**, **ffuf**, or proprietary internal tools) requires **zero frontend redesigns or tool-specific UI components**.

---

## Architectural Boundary Matrix

| System Layer | Knows Scanner-Specific Format? | Authority & Role |
|---|---|---|
| **Scanner Container Binary** | Yes | Generates raw tool stdout/stderr. |
| **Scanner Adapter / Parser** | **Yes (Translation Boundary)** | Normalizes raw stdout into `FindingCandidate` & `ScannerCoverage`. |
| **`FindingCandidate`** | **No** | Standardized platform domain record. |
| **Finding Database** | **No** | Authoritative Phase 8 findings schema. |
| **Provenance / Audit Layer** | **No** | Normalized snapshots, digests, and `PlanHash`. |
| **Frontend Dashboard** | **No** | Consumes platform-owned canonical DTOs. |

---

## Canonical Dashboard Read Models

The frontend UI displays scanning intelligence by consuming four platform DTOs:

### 1. Canonical Finding View (`FindingDetailDto`)
- **Severity**: Normalized `Critical`, `High`, `Medium`, `Low`, `Info`.
- **Classification**: Standardized `CweId` (e.g. `CWE-89`, `CWE-79`, `CWE-918`).
- **Location**: Normalized `EndpointPath`, `HttpMethod`, and line numbers.
- **Evidence**: Strictly redacted code snippets (`SanitizedEvidenceJson`).
- **Lifecycle**: `Detected`, `Triaged`, `RemediationPending`, `VerifiedResolved`.

### 2. Forensic Provenance Drawer (`ScanProvenanceResponse`)
- **Plan Verification**: Displays `PlanHash` and `PlannerVersion`.
- **Software Supply Chain**: Displays exact OCI `ContainerImageDigest` (`sha256:...`) and version for each tool executed.
- **Audit Chain**: Displays `RegistrySnapshotHash`, `PreviousAuditHash`, and `RecordHash`.
- **Rule Packs**: Displays versioned rule sets (e.g. `SemgrepRulePolicy: 2026.08.1`).
- **Execution Timeline**: Phased sequence (`Discovery` $\rightarrow$ `StaticAnalysis` $\rightarrow$ `ActiveVerification`).

### 3. AI Advisory Panel (`JsAiAdvisoryReport`)
- **Plain English Explanation**: Human-readable summary of the vulnerability.
- **Threat Scenario**: Potential attack vectors and business impact.
- **False-Positive Nuances**: Defense-in-depth or sanitizer context.
- **Remediation & Code Fix**: Concrete code examples and library recommendations.
- **Provenance**: `ModelIdentifier` and `PromptSchemaVersion` with `IsAdvisoryOnly: true`.

### 4. Tool Registry & Health Monitor (`ScanToolDto` / `ToolDiagnosticReport`)
- **Status**: `Healthy`, `Degraded`, `DisabledByPolicy`.
- **Capability Badges**: Disclosed capability tags (`sast.scan`, `dast.active_fuzz`, `api.fuzz`).
- **Profile Support**: `Standard`, `Deep`.
