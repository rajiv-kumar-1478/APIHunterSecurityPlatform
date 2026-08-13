# Tool Extensibility & Generic CLI Adapter Architecture

## Architectural Invariant

> **Adding or replacing a tool that conforms to the Generic CLI Tool Contract must require configuration/worker-image changes only, not modifications to core scan orchestration, domain models, API contracts, or dashboard code.**

---

## 1. Tool Registry & Capability Manifest

The tool registry (`SecurityScanTool` entity & `ScanToolRegistryService`) maintains metadata for all available hosted scanner binaries.

```text
Tool Definition
├── ToolKey (e.g., "httpx", "subfinder", "katana", "nuclei", "bughunter")
├── DisplayName
├── Version (pinned)
├── ImageReference / BinaryPath
├── ImageDigest
├── Required vs Optional
├── CapabilitiesJson (e.g., ["HttpProbing", "DnsResolution"])
├── HealthStatus (Healthy, Degraded, Missing, Unreachable, Disabled)
└── ResourceLimits (Timeout, MaxCpu, MaxMemoryMB)
```

---

## 2. Generic CLI Adapter Contract

Tools invoking command-line interfaces implement or map through `GenericCliToolAdapter`:

```csharp
public interface IGenericCliToolAdapter
{
    string ToolKey { get; }
    
    Task<ToolExecutionResult> ExecuteAsync(
        ToolExecutionRequest request, 
        ProviderSecretLease secretLease, 
        CancellationToken ct = default);
}
```

### CLI Execution Parameters

1. **Arguments Format**: Arguments are generated dynamically from configuration templates.
2. **Environment Variables**: Sensitive provider keys (`GROQ_API_KEY`, `VIRUSTOTAL_API_KEY`) are passed via process environment variables leased from `IScanProviderSecretStore` and purged immediately upon process completion.
3. **StdOut/StdErr Redirection**: Standard output and error streams are captured, parsed via JSON line parsers or regex matchers, and archived to object storage.
4. **Exit-Code Protocol**:
   - `0`: Success
   - `1-127`: Tool-specific warning or partial execution
   - `124/137`: Timed out or Killed by OS (Resource Limit)

---

## 3. Hosted-Mode Architecture & Resource Isolation

The API, Web Server, and Next.js Dashboard **never** assume scanning tools exist on the web server host. Scans are executed exclusively inside hosted worker containers (`Platform.Worker`).

### Resource Controls Enforced

- **Execution Timeout**: Default 15 minutes per tool execution; configurable per profile.
- **Memory Limit**: Enforced per tool execution container (default 1 GB RAM).
- **CPU Quota**: Constrained to allocated worker thread affinity.
- **Filesystem Isolation**: Tools execute inside temporary scratch volumes (`/tmp/scans/{job_id}`). Scratch space is wiped immediately upon completion.
- **Network Isolation**: Outbound traffic permitted only to target scope URLs and authorized API endpoints.

---

## 4. Configuration-Driven Tool Replacement & Runbook

To swap an existing tool (e.g. replace `subfinder` with `amass`):

1. **Update Container/Worker Image**: Install the new binary (`amass`) into the hosted worker container image.
2. **Register Tool Definition**: Add `amass` definition to `security_scan_tools` table with capability `SubdomainEnumeration`.
3. **Set Capability Priority**: Update `ScanToolRegistryService` configuration to prefer `amass` over `subfinder` for `SubdomainEnumeration`.
4. **Deploy Worker Update**: Deploy updated worker container.
5. **Zero Core Code Modifications**: Core scan orchestration (`ScanJobService`), API contracts (`SecurityScanController`), and Dashboard UI remain 100% untouched.

---

## 5. Upgrade & Rollback Strategy

1. **Side-by-Side Registration**: Register the upgraded tool version under `vNew` while keeping `vCurrent` enabled.
2. **Health Verification**: Startup health probe validates `vNew` binary binary presence and `--version` output.
3. **Canary Dispatch**: Route 10% of scan jobs to `vNew`.
4. **Promotion**: Promote `vNew` to default upon zero execution failures over 24 hours.
5. **Instant Rollback**: If `vNew` fails, toggle `vCurrent` back to default via configuration without code changes.
