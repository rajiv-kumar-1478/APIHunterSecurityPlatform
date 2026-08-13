# DEC-021: Generic CLI Tool Contract & Configuration-Driven Tool Replacement

- **Status**: Accepted & Locked (Phase 8)
- **Date**: 2026-08-13
- **Context**:
  The platform uses external security scanning tools (`subfinder`, `httpx`, `katana`, `nuclei`, `bughunter`). Hardcoding binary paths, CLI flags, or tool-specific logic into core orchestration services, domain entities, API controllers, or UI components creates tight coupling, making tool upgrades or replacements expensive and risky.
- **Decision**:
  1. **Configuration-Driven Replacement Invariant**: Adding or replacing a tool that conforms to the Generic CLI Tool Contract must require configuration/worker-image changes only, not modifications to core scan orchestration, domain models, API contracts, or dashboard code.
  2. **Capability-Based Scheduling**: Orchestration services request abstract capabilities (`SubdomainEnumeration`, `HttpProbing`, `UrlCrawling`, `VulnerabilityScanning`, `AiAssistedHunting`). The tool registry maps requested capabilities to available healthy tools dynamically.
  3. **Hosted Worker Execution Only**: Scanning tools run exclusively within hosted worker containers (`Platform.Worker`). Web servers and APIs never execute scanning binaries directly.
  4. **Strict Resource Isolation**: Execution timeouts, container memory limits, temporary scratch disk cleanup, and target scope network checks are enforced for all tool runs.
- **Impact**:
  Guaranteed tool extensibility. Security tools can be added, updated, or replaced cleanly via configuration and container updates without touching core platform domain code.
