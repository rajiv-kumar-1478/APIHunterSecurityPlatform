# Adding a New Scanner

A scanner is not operational until both its software contract and live isolation boundary are verified.

## Onboarding checklist

1. Identify canonical capability tags and target asset kinds.
2. Decide whether the tool conforms to the existing generic CLI/parser contract. If not, plan a typed adapter and parser.
3. Identify the authoritative upstream owner/repository and immutable release.
4. Obtain an official OCI image or approved artifact and record the exact `sha256:` digest; never use `:latest` or an invented version.
5. Document exact CLI/API arguments, authentication, exit codes, timeout, cancellation, artifacts, and output schema.
6. Define `ScanToolManifest` with verified version, digest, profiles, capabilities, asset types, and execution phase.
7. Implement a bounded parser with authentic golden fixtures, byte/candidate/evidence limits, and malformed-record diagnostics.
8. Implement the typed adapter when the generic contract is insufficient. Arguments must be deterministic and secret-free.
9. Register parser/adapter in API and worker DI only where required.
10. Add selection policy only when the tool is an approved provider for a capability.
11. Add manifest, argument, parser, resource-limit, scope, and `PlanHash` determinism tests.
12. Add unavailable-by-default tests proving missing runtime/provenance/credentials/egress fail closed with no host fallback.
13. Add integration tests for canonical ingestion, provenance, cancellation, scratch cleanup, and secret redaction.
14. Validate the image runs non-root with read-only root, dropped capabilities, finite CPU/memory/PID/time limits, and controlled writable mounts.
15. Prove egress permits only authorized targets and denies private, loopback, link-local, IMDS, DNS-rebinding, and unrelated public destinations.
16. Run live Docker tests and relevant PostgreSQL race tests. If the environment is missing, mark enablement blocked.
17. Update capability, operations, dashboard, and deployment documentation; then explicitly enable the tool through configuration.

## Configuration-only exception

Steps involving new code may be skipped only when the tool already conforms to an approved generic executable, existing parser/output schema, capability policy, and runtime contract. It still requires authoritative provenance, security tests, live isolation/egress evidence, and explicit enablement.
