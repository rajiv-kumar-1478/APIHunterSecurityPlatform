using System;
using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

public sealed record ScannerRuntimeOptions
{
    public ScannerRuntimeMode RuntimeMode { get; init; } = ScannerRuntimeMode.LocalDocker;

    public EgressGatewayMode EgressGatewayMode { get; init; } = EgressGatewayMode.EnforcedGateway;

    public string EgressNetworkName { get; init; } = "apihunter-sandbox-net";

    public string EgressGatewayEndpoint { get; init; } = "http://127.0.0.1:8888";

    public double MaxCpuCores { get; init; } = 2.0;

    public long MaxMemoryBytes { get; init; } = 1_073_741_824; // 1 GiB

    public int MaxPids { get; init; } = 100;

    public long MaxScratchDiskBytes { get; init; } = 524_288_000; // 500 MiB

    public TimeSpan ExecutionTimeout { get; init; } = TimeSpan.FromMinutes(10);

    public bool EnableReadOnlyRoot { get; init; } = true;

    public bool DropAllCapabilities { get; init; } = true;

    public bool NoNewPrivileges { get; init; } = true;

    public bool RequireDockerSandbox { get; init; } = false;

    public bool EnforceImageProvenance { get; init; } = true;

    public IReadOnlyList<string> TrustedImageRegistries { get; init; } = new[]
    {
        "ghcr.io/apihunter-security",
        "docker.io/apihunter",
        "quay.io/apihunter"
    };

    public bool AllowUnsafeProcessFallback { get; init; } = false;

    public string? HostedScannerServiceEndpoint { get; init; }

    public string? HostedScannerServiceKey { get; init; }

    public string PlatformScratchRoot { get; init; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "apihunter_scans");
}
