# SPEC-008: Scanner Capability Expansion Contract

## Status: 🔒 APPROVED / LOCKED

## 1. Executive Summary

SPEC-008 establishes the **Scanner Capability Expansion Contract** for the APIHunter Security Platform. It provides a formal, pluggable interface that allows adding any scanner into the platform with zero modifications to the Phase 9 continuous scheduling engine, Phase 8 ingestion orchestrator, reporting engines, or frontend dashboards.

---

## 2. Architectural Authority Model & Invariants

```text
ScanToolRegistry
       │
       ▼
ScanToolManifest (Immutable & Code-Controlled)
       │
   ┌───┴───────────────────────────────┐
   │ 1. Manifest & Digest Validation   │ (Authoritative sha256, SemVer, profile, capabilities)
   │ 2. Sandbox Policy Verification    │ (CPU/Mem limits, Drop-All, ReadOnlyRoot)
   └───┬───────────────────────────────┘
       ▼
IScanToolAdapter (Pure Capability Translation)
       │ PrepareExecution()
       ▼
ToolExecutionPlan
       │
       ▼
ScannerRuntimeSandbox (Authoritative Sandbox Execution)
       │ ──► Generates Authoritative ToolExecutionReceipt (Actual exit, digest, duration)
       │ ──► Captures raw stdout/stderr
       ▼
IScanToolAdapter.ParseOutputAsync()
       │
       ▼
FindingCandidate (Raw parsed evidence & structural identity material)
       │
       ▼
EvidenceSanitizer (Platform-Owned Authoritative Security Boundary)
       │ ──► Redacts tokens, keys, PII, enforces size ceilings
       ▼
FindingFingerprintService (Platform-Owned Canonical v1 Fingerprint)
       │ ──► Computes canonical cross-scanner fingerprint SHA-256 (v1 algorithm)
       ▼
ScanFindingIngestionEngine
       │
   ┌───┴───────────────────────────────┐
   ▼                                   ▼
SecurityFinding & Evidence DB       ScannerCoverage (Bounded)
   │                                   │
   ▼                                   ▼
Phase 8 Lifecycle & Diff             Phase 9 Continuous Campaigns
```

### 2.1 Critical Negative Invariants
A scanner adapter **MUST NEVER**:
1. ❌ Create or mutate `SecurityFinding` or `SecurityFindingEvidence` database entities directly.
2. ❌ Declare evidence "safe" or bypass `EvidenceSanitizer`.
3. ❌ Generate or declare its own `ToolExecutionReceipt` (receipt authority is the Sandbox runtime).
4. ❌ Calculate its own arbitrary fingerprint key (fingerprint authority is the Platform).
5. ❌ Modify `SecurityScanJob` status, progress, version, or failure lifecycle.
6. ❌ Calculate, schedule, or interact with `ScanCampaign` state.
7. ❌ Execute commands directly on the host or bypass `IScannerRuntimeSandbox`.

---

## 3. Canonical v1 Fingerprint Specification

To guarantee that Phase 9's finding lifecycle (`Persistent` $\rightarrow$ `NotObserved` $\rightarrow$ `Resolved`) remains 100% deterministic and unaffected by scanner upgrades or cross-tool overlaps, the platform owns the **v1 Canonical Fingerprint Algorithm**:

```text
CanonicalFingerprintInput =
    "v1\n"
    + CanonicalTargetUrl + "\n"
    + CanonicalFindingType + "\n"
    + CanonicalHttpMethod + "\n"
    + CanonicalParameter + "\n"
    + CanonicalVulnerableLocation + "\n"
    + CanonicalRuleOrTemplateId
```

### 3.1 Field Normalization Rules

| Field | Normalization & Invariants |
|---|---|
| **Version Prefix** | Constant `"v1"` |
| **`CanonicalTargetUrl`** | Lowercase scheme and host (`https://api.example.com`). Default ports removed (`:80`, `:443`). Trailing slash stripped from root paths (`https://api.example.com/` $\rightarrow$ `https://api.example.com`). Fragments (`#...`) stripped. Query parameters sorted alphabetically (`?a=1&b=2`). |
| **`CanonicalFindingType`** | Lowercase, trimmed, spaces replaced with hyphens (e.g. `cwe-89-sql-injection`, `exposed-jwt-secret`). |
| **`CanonicalHttpMethod`** | Uppercase trimmed (`GET`, `POST`, `PUT`, `DELETE`), or `""` if not an HTTP-specific finding. |
| **`CanonicalParameter`** | Lowercase trimmed (e.g. `id`, `redirect_uri`), or `""` if not parameter-specific. |
| **`CanonicalVulnerableLocation`** | Lowercase trimmed path, header, or JSON pointer (e.g. `/api/v1/auth/login`, `header:authorization`), or `""`. |
| **`CanonicalRuleOrTemplateId`** | Lowercase trimmed scanner rule (e.g. `cve-2023-12345`, `auth-bypass`), or `""`. |
| **Null Representation** | All null values normalize to `""` (empty string), preserving newline positions. |
| **Unicode Normalization** | Normalization Form C (NFC) applied before hashing. |
| **Output Hash** | `SHA-256(CanonicalFingerprintInput)` rendered as a **64-character lowercase hex string**. |

---

## 4. Manifest & Version Validation Specification

### 4.1 Syntax Validation Rules
- **`ToolKey`**: Lowercase alphanumeric + hyphen: `^[a-z0-9-]+$` (e.g. `httpx`, `nuclei`, `subfinder`, `jsminer`, `bughunter`).
- **`Version`**: SemVer / Calendar / Build format: `^v?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$` (e.g. `1.2.3`, `v2.4.0`, `2026.08`, `1.0.0-beta.1`).
- **`ContainerImageDigest`**: Exact sha256 format: `^sha256:[a-f0-9]{64}$`.
- **`SupportedProfiles`**: Must contain at least one valid profile (`Recon`, `Standard`, `Deep`).
- **`Capabilities`**: Non-empty set of capability tags.

---

## 5. Bounded Scanner Coverage

```csharp
public sealed record ScannerCoverage(
    int EndpointsDiscovered,
    int ParametersExtracted,
    int AssetsProbed,
    int JavaScriptFilesDiscovered,
    bool CoverageTruncated,
    string? CoverageArtifactReference,
    IReadOnlyDictionary<string, object> CoverageDetails
);
```

---

## 6. Phased Implementation Roadmap

- **SPEC-008.1**: Contract Infrastructure & Validation (`ScanToolManifest`, `IScanToolAdapter`, `IScanToolRegistry`, `FindingFingerprintService`, `ScanToolManifestValidator`).
- **SPEC-008.2**: Existing Adapter Migration (`Httpx`, `Nuclei`, `Subfinder`) & OCI Container Provenance Verifier.
- **SPEC-008.3**: `JsMinerAdapter` (Adversarial line streaming parser, resource bounds, discovery vs. vulnerability separation).
- **SPEC-008.4**: Multi-Layered JavaScript Intelligence Pipeline:
  - **SPEC-008.4.1**: JavaScript Asset Inventory, Content Hashing (`SHA-256`) & Deployment Change Diffing.
  - **SPEC-008.4.2**: ECMAScript AST Parsing (`Acornima`), Bounded Constant Folding, GraphQL/WebSocket Extraction & Attack-Surface Graph.
  - **SPEC-008.4.3**: Sensitive-Value & Secret Intelligence, AST Context Correlation, Shannon Entropy & Cross-Chunk Deduplication.
- **SPEC-008.5**: Attack Surface $\rightarrow$ BugHunter Verification Bridge & Secure Deployment Webhooks (HMAC-SHA256, Replay Prevention, Server-Side Target Resolution).
- **SPEC-008.6**: Continuous Intelligence Orchestration & Deployment Scan Lifecycle.

---

## 7. Future Scanner Extension Contract

Any future security tool (e.g., **OWASP ZAP**, **Semgrep**, **TruffleHog**, **ffuf**, **Kiterunner**, **Caido**, **Trivy**, etc.) integrates into APIHunter strictly through the pluggable adapter model:

1. **Contractual Integration Point**:
   - Implement [`IScanToolAdapter`](file:///c:/Users/rk170/Desktop/APIHunterSecurityPlatform/src/Platform.Application/Scanning/Adapters/IScanToolAdapter.cs).
   - Declare an immutable [`ScanToolManifest`](file:///c:/Users/rk170/Desktop/APIHunterSecurityPlatform/src/Platform.Application/Scanning/Contracts/ScanToolManifest.cs) with an authentic OCI container image reference and cryptographic digest (`sha256:...`).
   - Register in [`IScanToolRegistry`](file:///c:/Users/rk170/Desktop/APIHunterSecurityPlatform/src/Platform.Application/Scanning/Adapters/IScanToolRegistry.cs).

2. **Immutable Boundary Invariants**:
   Adding a new tool **MUST NEVER**:
   - 🔒 Modify Phase 9 continuous campaign scheduler or cron mechanics.
   - 🔒 Bypass or alter tenant isolation and authorized target boundary rules.
   - 🔒 Bypass the Phase 8 Docker sandbox runtime (`IScannerRuntimeSandbox`).
   - 🔒 Bypass `EvidenceSanitizer` or declare raw scanner output inherently "safe".
   - 🔒 Alter the platform-owned `FindingFingerprintService` canonical v1 identity algorithm.
   - 🔒 Directly write to or mutate `SecurityFinding` entities or database lifecycle states.
