# BugHunter Integration & Provider Specification

## Overview

BugHunter is an external security scanning toolchain integrated into the APIHunter Security Intelligence Platform via an isolated provider adapter (`IBugHunterProvider` / `BugHunterScanProvider`).

The platform orchestrates scans by requesting high-level capabilities (`SubdomainEnumeration`, `HttpProbing`, `UrlCrawling`, `VulnerabilityScanning`, `AiAssistedHunting`, `ReportGeneration`), rather than coupling business logic directly to BugHunter CLI internal syntax.

---

## Architecture Boundary

```text
                     APIHunter Security Platform
                                 │
                                 ▼
                           IScanProvider
                                 │
                        IBugHunterProvider
                                 │
                       BugHunterScanProvider
                        (Infrastructure Stub)
                                 │
               ┌─────────────────┴─────────────────┐
               ▼                                   ▼
        Hosted Worker                       CLI / Toolchain
```

- **Upstream Repository**: [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
- **Pinned Version / Commit**: Verified during Phase 8 Step 2 runtime installation.
- **Provider Key**: `bughunter`
- **Supported Capabilities**: `SubdomainEnumeration`, `DnsResolution`, `HttpProbing`, `UrlCrawling`, `VulnerabilityScanning`, `AiAssistedHunting`, `ReportGeneration`

---

## Key Security & Secret Principles

1. **Zero Secret Persistence**: Raw API keys (e.g. `GROQ_API_KEY`, `VIRUSTOTAL_API_KEY`) are resolved at runtime via `IScanProviderSecretStore` and leased in-memory during execution.
2. **Scope Authorization**: Scans are permitted only against authorized security targets registered in `SecurityTarget`.
3. **Optimistic Concurrency**: `SecurityScanJob.Version` uses optimistic concurrency control to prevent duplicate or conflicting execution updates.

---

## Step-by-Step Procedure to Replace BugHunter

If BugHunter needs to be replaced with another scanner (e.g. `CustomSecurityScanner`, `ZAP`, `ProjectDiscovery Suite`):

1. **Implement Provider Interface**: Create a new class implementing `IScanProvider` in `Platform.Infrastructure/Scanning/`.
2. **Create Adapter**: Implement execution request handling, tool invocation, exit-code mapping, and artifact collection.
3. **Map Canonical Results**: Normalize tool outputs into canonical `ScanResult` DTOs.
4. **Implement Tool Health Check**: Register health probes in `IScanToolHealthService`.
5. **Register Provider**: Register the new provider implementation in `Program.cs` under its own `ProviderKey`.
6. **Publish Capability Manifest**: Register tool capability mappings in `ScanToolRegistryService`.
7. **Run Contract Tests**: Execute `ScanProviderContractTests` to verify interface compliance.
8. **Execute Parallel Comparison**: Run parallel comparison scans against test targets to validate findings accuracy.
9. **Switch Active Provider**: Update default `ProviderKey` configuration or endpoint parameter to route scan jobs to the new provider.
10. **Rollback Safety**: Maintain BugHunter provider registration in disabled state during the migration rollback window.
