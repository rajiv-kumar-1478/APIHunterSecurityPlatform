# Security Scan Provider Contract Specification

## Boundary

`IScanProvider` is the hosted-provider compatibility contract. It does not make a provider operational and it is not the only scanner abstraction in the platform.

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

Operational tool execution flows through capability planning, tool adapters, and `IScannerRuntimeSandbox`. A provider implementation may expose stable unavailable behavior without executing a tool. BugHunter currently does exactly that.

## Contract invariants

1. **Explicit availability**: Unconfigured or contract-incomplete providers return stable blocked/unavailable results. They never fabricate external IDs, progress, findings, artifacts, health, or cancellation success.
2. **No host fallback**: An unavailable container/hosted runtime must not silently execute a scanner process on the API or worker host.
3. **Sanitized DTOs**: Requests/results contain canonical metadata only. Raw provider secrets never appear in DTOs, logs, persistence, or command-line arguments.
4. **Tenant and scope authority**: Required `SecurityScanJob.TenantId` and registered target scope are revalidated before any secret lease or tool execution. `RequestedByUserId` is optional provenance, not ownership.
5. **Canonical status**: Providers map outcomes to platform states such as `CompletedWithWarnings`, `Partial`, `TimedOut`, `Blocked`, or unavailable-specific codes.
6. **Runtime isolation**: Operational execution requires an authoritative image/CLI/API contract, digest provenance, non-root sandboxing, resource limits, cancellation semantics, and enforced egress.

## Current provider status

`BugHunterScanProvider` is a compatibility descriptor only. All execution/status/result/cancel paths remain unavailable with `BUGHUNTER_CONTRACT_UNAVAILABLE` until the authoritative contract and live isolation evidence exist.
