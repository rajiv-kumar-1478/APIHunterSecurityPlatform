# Security Scan Provider Contract Specification

## Interface Definition

All scanner providers implement the `IScanProvider` interface:

```csharp
public interface IScanProvider
{
    string ProviderKey { get; }

    Task<ScanStartResult> StartAsync(ScanExecutionRequest request, CancellationToken ct = default);

    Task<ScanStatusResult> GetStatusAsync(string externalScanId, CancellationToken ct = default);

    Task<ScanResult> GetResultAsync(string externalScanId, CancellationToken ct = default);

    Task CancelAsync(string externalScanId, CancellationToken ct = default);
}
```

---

## Contract Invariants

1. **Provider Isolation**: Application code never interacts with tool-specific binaries directly. All tool dispatch flows through `IScanProvider`.
2. **Sanitized Input/Output DTOs**: DTOs carry sanitized metadata only (`ScanExecutionRequest`, `ScanExecutionResult`, `ToolExecutionResult`). Secrets are never embedded in DTO properties.
3. **Graceful Status Model**: Scan statuses support `CompletedWithWarnings`, `Partial`, `TimedOut`, and `Blocked` to handle partial tool failure modes in complex scanning environments.
