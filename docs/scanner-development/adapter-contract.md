# Scanner Adapter Contract

## `IScanToolAdapter` Interface

Every security scanner in APIHunter must implement `Platform.Application.Scanning.Adapters.IScanToolAdapter`:

```csharp
public interface IScanToolAdapter
{
    /// <summary>
    /// Immutable, code-controlled software supply chain manifest.
    /// </summary>
    ScanToolManifest Manifest { get; }

    /// <summary>
    /// Prepares CLI execution arguments and environment variables for the sandbox.
    /// </summary>
    ToolExecutionPlan PrepareExecution(ScanExecutionContext context);

    /// <summary>
    /// Parses raw stdout/stderr output into standardized FindingCandidate records.
    /// </summary>
    Task<ToolParsedOutputResult> ParseOutputAsync(
        ScanExecutionContext context,
        ToolExecutionRawOutput rawOutput,
        CancellationToken ct = default);
}
```

---

## Adapter Responsibilities & Invariants

1. **Deterministic Arguments**:
   - `PrepareExecution` must be a pure, side-effect-free transformation of `ScanExecutionContext` into `ToolExecutionPlan`.
   - Must never make network requests or read files outside the sandbox mount directory.

2. **Scoped Execution**:
   - The adapter must strictly honor `context.TargetUrl` and never widen scope beyond the authorized target.

3. **Isolated Parsing**:
   - `ParseOutputAsync` must delegate parsing to a dedicated, bounded `XxxOutputParser`.
   - Malformed stdout/stderr from the scanner container must never crash the worker process.

4. **Zero Phase 9 Knowledge**:
   - Adapters must never reference the campaign scheduler, tenant DB contexts, or background queue abstractions.
