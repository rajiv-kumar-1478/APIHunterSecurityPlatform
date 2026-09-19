# DEC-021: Generic CLI Tool Contract & Configuration-Driven Tool Replacement

- **Status**: Accepted; operational scope clarified by DEC-022
- **Original date**: 2026-08-13
- **Clarified**: 2026-09-05
- **Context**: Hardcoded binary paths and tool syntax create unsafe coupling, but claiming every scanner is configuration-only hides parser, provenance, sandbox, and egress requirements.
- **Decision**:
  1. **Configuration-only scope**: Configuration/image changes are sufficient only when a tool already conforms to the approved generic executable, arguments, parser/output, capability, provenance, sandbox, and egress contracts.
  2. **Typed extensions**: A new CLI/output schema, capability policy, or adapter requires code, DI registration, authentic fixtures, and tests. Core domain/API/dashboard contracts remain canonical and scanner-independent.
  3. **Capability scheduling**: Planning selects only enabled, healthy, provenance-valid tools supported by an operational runtime. Capability intent alone is not health.
  4. **Sandbox-only execution**: Tools execute only through `IScannerRuntimeSandbox`; API/worker host fallback is forbidden.
  5. **Fail-closed isolation**: Timeouts, process-tree termination, resource limits, scratch cleanup, target scope, immutable image provenance, and enforced egress are mandatory. Missing boundaries return a stable unavailable/security-boundary result.
- **Impact**: Conforming tools remain replaceable without changing canonical platform contracts, while non-conforming or unverified tools cannot be mislabeled operational.
