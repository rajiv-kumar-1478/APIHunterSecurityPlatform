# Sandbox Execution & Isolation Requirements

## Status

These are normative requirements for an operational `IScannerRuntimeSandbox`. The checked-in production/Compose runtime is currently disabled and fail-closed. Non-root API/worker/frontend images do not by themselves prove scanner-container isolation.

## Required scanner boundary

1. **No host fallback**: Scanner binaries execute only inside the approved executor. Missing executor configuration returns a stable fail-closed result.
2. **Non-root**: Fixed unprivileged UID/GID with no privilege escalation.
3. **Dropped capabilities**: Drop all Linux capabilities unless an individually reviewed capability is unavoidable.
4. **Read-only root**: Only bounded, purpose-specific scratch/tmpfs mounts are writable.
5. **Resource limits**: Enforce finite memory, CPU, PID, output-size, and wall-clock limits at the container/executor layer.
6. **Immutable image**: Exact repository plus `sha256:` digest; mutable tags and unverified images are rejected.
7. **Process/container termination**: Timeout, cancellation, or lease loss terminates the exact execution tree and waits for cleanup.
8. **Scratch isolation**: Per-job anchored paths, no traversal/symlink/reparse-point escape, and guaranteed cleanup.
9. **Enforced egress**: All network traffic crosses a physical gateway/network boundary. Allow only authorized target destinations; deny loopback, private, link-local, IMDS, DNS-rebinding changes, and unrelated public hosts.
10. **Secret handling**: Lease only required secrets into transient memory/environment; never command lines, logs, artifacts, DTOs, or persistence.

## Live evidence required

Unit and mock tests validate contracts but cannot prove container/network isolation. Before enabling a runtime, live tests must inspect effective user/capabilities/mounts/limits, exercise allowed and denied egress, verify cancellation/cleanup, and verify fail-closed behavior for missing provenance, gateway, credentials, or provider contract.

If Docker or the target executor is unavailable, record this gate as blocked and keep runtime mode disabled.
