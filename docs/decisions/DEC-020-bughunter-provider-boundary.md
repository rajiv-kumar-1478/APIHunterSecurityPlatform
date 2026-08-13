# DEC-020: BugHunter Scan Provider Boundary & Replacement Architecture

- **Status**: Accepted & Locked (Phase 8 Step 1)
- **Date**: 2026-08-13
- **Context**:
  The platform integrates BugHunter and associated ProjectDiscovery security tools (`subfinder`, `httpx`, `katana`, `nuclei`) for hosted scanning capability. BugHunter is an active external toolchain. The platform architecture must prevent BugHunter CLI syntax or package dependencies from leaking into core domain or application business logic.
- **Decision**:
  1. **Provider Adapter Boundary**: BugHunter is integrated strictly via `IBugHunterProvider` / `IScanProvider` abstraction. No core domain or application logic invokes `bughunter` CLI commands directly.
  2. **Capability-Based Scheduling**: Jobs request high-level capabilities (`SubdomainEnumeration`, `HttpProbing`, `VulnerabilityScanning`, `AiAssistedHunting`), mapped dynamically via `ScanToolRegistryService`.
  3. **Secret Isolation**: Provider secrets (`GROQ_API_KEY`, `VIRUSTOTAL_API_KEY`) are resolved via `IScanProviderSecretStore`. `InMemoryScanProviderSecretStore` is strictly scoped for `Development/Test` environments; production uses `ConfigurationScanProviderSecretStore` integrated with `IDataProtectionProvider`.
  4. **Reversible Provider Architecture**: Replacing BugHunter requires implementing `IScanProvider`, mapping canonical DTOs, and updating DI registration. Zero changes to security findings, graph intelligence, or core platform domain models are required.
- **Impact**:
  Guaranteed 100% provider isolation. BugHunter can be upgraded, swapped, or replaced without architectural drift or core engine refactoring.
