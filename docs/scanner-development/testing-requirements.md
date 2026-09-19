# Scanner Plugin Testing Requirements

Scanner readiness has separate evidence tiers. Passing an earlier tier does not imply operational availability.

## Tier 1 — deterministic unit contracts
- Validate authoritative manifest fields, exact version, repository, and `sha256:` digest.
- Validate deterministic, shell-free, secret-free execution arguments.
- Parse authentic golden output into canonical findings and coverage.
- Enforce raw-byte, candidate-count, evidence-size, malformed-record, and cancellation bounds.
- Verify capability selection and deterministic `PlanHash`.
- Verify unavailable/missing configuration returns stable fail-closed results.

## Tier 2 — application integration
- Verify tenant target/scope authorization before secrets or execution.
- Verify canonical ingestion, deduplication, sanitized evidence, reports, provenance, and invocation records.
- Verify secret leases and scratch directories are cleaned on success, failure, timeout, cancellation, and lease loss.
- Verify disabled runtime/provider never launches a host process or fabricates external state.
- Verify UI/API expose `Unavailable`, `NotConfigured`, and fail-closed diagnostics truthfully.

## Tier 3 — live container and network boundary
Requires Docker or the real managed executor:
- inspect non-root UID, read-only root, dropped capabilities, mounts, and CPU/memory/PID limits;
- execute a digest-pinned image and reject mutable/unapproved artifacts;
- prove authorized target egress succeeds;
- prove loopback/private/link-local/IMDS/DNS-rebinding/unapproved egress fails;
- prove timeout/cancellation kills the exact process/container tree and removes scratch/artifacts;
- prove missing gateway/credentials/provider contract keeps readiness false.

## Tier 4 — relational concurrency and migration
Requires real PostgreSQL:
- apply the full migration chain to an empty database and inspect the final schema;
- run idempotency, claim, heartbeat/recovery, and scheduler race tests with independent DbContexts/processes;
- prove exactly-once campaign occurrence and retry-safe outcome markers.

## Reporting rule

Mock/in-memory checks may pass while live Docker or PostgreSQL checks are blocked. Report each tier separately. Never relabel a blocked environment gate as passed, and never enable a scanner based only on unit/parser/manifest evidence.
