# Hosted Scan Execution Architecture Specification

## Overview

The hosted scan execution pipeline coordinates security scanning jobs across registered targets while strictly enforcing scope authorization, worker isolation, and zero-secret persistence boundaries.

---

## Scan Job Lifecycle

```text
                     Security Center API
                             │
                             ▼
                    POST /security/scans/jobs
                             │
                             ├── Scope Authorization Verification
                             ├── Target Registration Validation
                             └── Profile Tool Capability Check
                             │
                             ▼
                    SecurityScanJob (Status: Queued)
                             │
                             ▼
                    Durable Job Queue (PostgreSQL SKIP LOCKED)
                             │
                             ▼
                      Hosted Scan Worker
                             │
                             ├── Claim Job (Version++)
                             ├── Acquire Secret Lease (IScanProviderSecretStore)
                             ├── Check Tool Capabilities (IScanToolHealthService)
                             ├── Execute Provider (IScanProvider)
                             ├── Collect Tool Execution Artifacts
                             └── Release Secret Lease
                             │
                             ▼
                     Scan Result Normalization
```

---

## Scan Profiles & Capability Requirements

- **Recon Profile**: Requires `SubdomainEnumeration`, `DnsResolution`, `HttpProbing`.
- **WebAssessment Profile**: Requires `HttpProbing`, `UrlCrawling`, `VulnerabilityScanning`.
- **FullAssessment Profile**: Requires `SubdomainEnumeration`, `DnsResolution`, `HttpProbing`, `UrlCrawling`, `VulnerabilityScanning`, `AiAssistedHunting`, `ReportGeneration`.
