# Tool Extensibility & Generic CLI Adapter Architecture

## Architectural Invariants & Security Boundaries

> **Invariant 1**: Adding or replacing a tool that conforms to the Generic CLI Tool Contract must require configuration/database manifest changes only, not modifications to core scan orchestration, adapter code, domain models, or API contracts. Adding a tool such as `dnsx` requires zero code edits.

> **Invariant 2**: Target scope authorization is **fail-closed**. Target hostnames must match exact target domains or authorized subdomains (`host == targetHost || host.EndsWith("." + targetHost)`). Prefix/suffix lookalikes (e.g. `evil-example.com`, `example.com.attacker.io`) are strictly denied.

> **Invariant 3**: Secrets are leased in-memory during worker process execution via `ProviderSecretLease`. `ProviderSecretLease.Dispose()` releases platform-controlled secret container references. Raw secrets are strictly forbidden from database rows, DTOs, logs, and CLI argument strings.

---

## 1. Tool Registry & Manifest-Driven Executable Resolution

The tool registry (`SecurityScanTool` entity & `ScanToolRegistryService`) maintains metadata for all available scanner binaries, including the persisted `Executable` column.

### Executable Validation at Registration & Execution
1. **Name Format**: Must match regex `^[a-zA-Z0-9_\-\.]+$`.
2. **Prohibited Path Separators & Traversal**: Paths containing `..`, `/`, `\`, or absolute path specifiers are strictly rejected.
3. **Prohibited Shell Interpreters**: Shell interpreters (`cmd`, `powershell`, `bash`, `sh`, `zsh`, `csh`, `wscript`, `cscript`, `python`, `perl`, `ruby`) are strictly denied.
4. **Dynamic Manifest Resolution**: `GenericScanWorker` resolves `tool.Executable` directly from `SecurityScanTool` database definitions and dispatches `ToolExecutionRequest(..., Executable: tool.Executable)`. `GenericCliToolAdapter` resolves `request.Executable` without relying on hardcoded static tool lists in source code.

---

## 2. Registry Capability Resolution vs Worker Health Filtering

- **ScanToolRegistryService.GetToolsForCapabilitiesAsync()**: Queries enabled tools in the database registry (`Enabled == true`) matching the required profile capabilities.
- **GenericScanWorker**: Performs health filtering (`tool.HealthStatus == ToolHealthStatus.Healthy`) immediately before launching each tool. Unhealthy or disabled tools are logged and skipped. If a `Required` tool is unhealthy or fails execution, the scan job is aborted with `SecurityScanJobStatus.Failed`.

---

## 3. Generic CLI Adapter Contract (`IGenericCliToolAdapter`)

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

## 4. Hosted Execution & Filesystem Isolation Guards

Scratch directories are generated under an anchored root (`<WorkerScratchRoot>/scans/{JobId}`).

1. **Path Prefix Guard**: `ValidateScratchDirectoryPath` verifies canonical path component prefix anchoring without substring exceptions.
2. **Symlink/Junction Guard**: `VerifyNoReparsePointOrSymlink` rejects directory paths containing symlinks or reparse points.
3. **Guaranteed Cleanup**: `GenericScanWorker` deletes scratch directories recursively inside a `finally` block.

---

## 5. Production Secret Store Policy

`ConfigurationScanProviderSecretStore` enforces ASP.NET Core `IDataProtectionProvider` (`CfDJ8` prefix). Plaintext secret values in production configurations are rejected with a security exception. Plaintext fallback is permitted strictly in `Development` or `Testing` environments.

---

## 6. Implementation Scope vs Future Container Hardening

### Implemented in Phase 8 Step 1 (Local Process Worker Foundation)
- Secret lease disposal reference release.
- Manifest-driven executable resolution & validation.
- Fail-closed target scope verification with exact & subdomain matching.
- Output & exception log secret masking (`SanitizeOutput`).
- Scratch directory allocation and guaranteed `finally` cleanup.
- Deterministic tool replacement via database manifest.

### Future Infrastructure Hardening (Container Workers)
- Container cgroup CPU & Memory quota limits.
- Container image digest pinning (`ImageDigest`).
- Non-root container UID execution.
- NetworkPolicy egress restriction and private-network IP resolution validation (SSRF / link-local blocking).
