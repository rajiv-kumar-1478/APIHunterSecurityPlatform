# Tool Extensibility & Generic CLI Adapter Architecture

## Scope of configuration-only onboarding

A tool can be added by manifest/configuration only when it already conforms to the approved generic CLI contract: one validated executable name, deterministic arguments, an existing compatible parser/output contract, immutable provenance, and the configured sandbox/egress boundary. A new typed adapter, parser, capability policy, or output schema requires code and tests.

## Security invariants

1. **Fail-closed scope**: The target host must equal the registered host or an authorized subdomain. Prefix/suffix lookalikes and private/link-local destinations are denied.
2. **Executable allowlisting**: Executables match `^[a-zA-Z0-9_.-]+$`; path separators, traversal, absolute paths, and shell/script interpreters are rejected.
3. **Secret isolation**: `ProviderSecretLease` values remain transient memory only. They are forbidden in database rows, DTOs, logs, artifacts, and CLI arguments.
4. **Immutable provenance**: Operational tools require authoritative version and digest metadata. Placeholder versions and mutable tags are not valid proof.
5. **No runtime fallback**: Disabled or unavailable sandbox execution returns a stable security-boundary failure and may not launch on the API/worker host.

## Registry and adapter flow

```text
SecurityScanTool manifest
        │
        ├─ enabled + healthy + capability match
        ├─ validated executable and provenance
        ▼
ToolExecutionRequest
        ▼
IScannerRuntimeSandbox
        ▼
IGenericCliToolAdapter / typed IScanToolAdapter
        ▼
bounded parser → FindingCandidate → sanitized ingestion
```

`GenericCliToolAdapter` maps exit codes and cancellation to canonical `ToolExecutionResult` values. Scratch paths are anchored, symlink/reparse-point guarded, and deleted in a `finally` path.

## Isolation implementation versus operational gate

The codebase defines digest provenance checks, non-root sandbox requirements, resource limits, scratch isolation, process-tree termination, SSRF-aware egress policy, and enforced-gateway contracts. API, worker, and frontend images are non-root.

Those controls do **not** prove that a live scanner container is isolated. Default/Compose scanner execution remains disabled until an authoritative executor/image and physical egress boundary are configured and live Docker tests validate the complete path.
