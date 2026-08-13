# Tool Extensibility & Generic CLI Adapter Architecture

## Architectural Invariants & Security Boundaries

> **Invariant 1**: Adding or replacing a tool that conforms to the Generic CLI Tool Contract must require configuration/worker-image changes only, not modifications to core scan orchestration, domain models, API contracts, or dashboard code.

> **Invariant 2**: Target scope authorization is **fail-closed**. If zero targets are registered or a target host is unauthorized, scan job creation is strictly rejected.

> **Invariant 3**: Secrets are leased in-memory during worker process execution via `ProviderSecretLease`. `ProviderSecretLease.Dispose()` zero-clears secret entries. Secrets are strictly forbidden from database rows, DTOs, logs, and CLI argument strings.

---

## 1. Tool Registry & Whitelisted Binary Execution

The tool registry (`SecurityScanTool` entity & `ScanToolRegistryService`) maintains metadata for all available scanner binaries.

`GenericCliToolAdapter` validates all requested binary names against an explicit whitelist (`subfinder`, `httpx`, `katana`, `nuclei`, `bughunter`, `amass`, `nmap`, `ffuf`, `powershell.exe`, `cmd.exe`). Unregistered binary keys are rejected with `BINARY_NOT_REGISTERED` security violations.

---

## 2. Generic CLI Adapter Contract (`IGenericCliToolAdapter`)

```csharp
public interface IGenericCliToolAdapter
{
    string ToolKey { get; }
    
    Task<ToolExecutionResult> ExecuteAsync(
        ToolExecutionRequest request, 
        ProviderSecretLease secretLease, 
        string scratchDirectory, 
        CancellationToken ct = default);
}
```

### Exit-Code Semantics & Disambiguation

- `0` => `ToolExecutionStatus.Success`
- `1-127` (without cancellation token trigger) => `ToolExecutionStatus.Failed` with `ExitCode = N` and `ErrorCode = "EXIT_CODE_N"`
- Timeout / Cancellation => `ToolExecutionStatus.TimedOut` with `ErrorCode = "TIMED_OUT"` or `"CANCELLED"`, process tree terminated immediately via `KillProcessTreeSafely(entireProcessTree: true)`.

---

## 3. Hosted Execution & Filesystem Isolation Guards

Scratch directories are generated under an anchored root (`<WorkerScratchRoot>/scans/{JobId}`).

1. **Path Prefix Guard**: `ValidateScratchDirectoryPath` verifies canonical path prefix anchoring without substring exceptions.
2. **Symlink/Junction Guard**: `VerifyNoReparsePointOrSymlink` rejects directory paths containing symlinks or reparse points.
3. **Guaranteed Cleanup**: `GenericScanWorker` deletes scratch directories recursively inside a `finally` block.

---

## 4. Production Secret Store Policy

`ConfigurationScanProviderSecretStore` enforces ASP.NET Core `IDataProtectionProvider` (`CfDJ8` prefix). Plaintext secret values in production configurations are rejected with a security exception. Plaintext fallback is permitted strictly in `Development` or `Testing` environments.

---

## 5. Implementation Scope vs Future Container Hardening

### Implemented in Phase 8 Step 1 (Local Process Worker Foundation)
- Secret lease zero-clearing on disposal.
- Whitelisted binary execution guard.
- Canonical path prefix anchoring & symlink/reparse point checks.
- Fail-closed target scope verification.
- Output & exception log secret masking (`SanitizeOutput`).
- Deterministic tool replacement via registry.

### Future Infrastructure Hardening (Container Workers)
- Container cgroup CPU & Memory quota limits.
- Container image digest pinning (`ImageDigest`).
- Non-root container UID execution.
- NetworkPolicy egress restriction per target domain.
