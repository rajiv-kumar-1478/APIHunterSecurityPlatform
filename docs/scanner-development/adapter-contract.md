# Scanner Adapter Contract

## Adapter types

Every **operational typed scanner adapter** implements `Platform.Application.Scanning.Adapters.IScanToolAdapter`. Tools that already satisfy the generic CLI executable/parser contract may use the generic adapter path. Hosted-provider compatibility implementations such as the currently unavailable BugHunter provider are a separate boundary.

```csharp
public interface IScanToolAdapter
{
    ScanToolManifest Manifest { get; }
    ToolExecutionPlan PrepareExecution(ScanExecutionContext context);
    Task<ToolParsedOutputResult> ParseOutputAsync(
        ScanExecutionContext context,
        ToolExecutionRawOutput rawOutput,
        CancellationToken ct = default);
}
```

## Responsibilities and invariants

1. **Authoritative manifest**: Version, repository, digest, capabilities, target kinds, and profiles must be verified. Placeholder values and mutable tags are invalid.
2. **Deterministic execution plan**: `PrepareExecution` is side-effect-free, emits no shell command, and never places a secret in arguments.
3. **Scoped execution**: Arguments cannot widen the registered tenant target or introduce candidate-controlled destinations.
4. **Runtime-only execution**: Adapters prepare and parse; they do not bypass `IScannerRuntimeSandbox` or launch host processes.
5. **Bounded parsing**: Delegate to a bounded parser. Malformed or adversarial output cannot crash or exhaust the worker.
6. **Canonical output**: Return `FindingCandidate`, coverage, and diagnostics only. Raw scanner formats do not cross into persistence/UI contracts.
7. **Zero scheduler coupling**: Adapters do not reference campaigns, tenant DbContexts, claims, or background queue abstractions.
8. **Truthful availability**: Registration or parser success is not health. If the runtime or required contract is unavailable, execution remains disabled/fail-closed.
