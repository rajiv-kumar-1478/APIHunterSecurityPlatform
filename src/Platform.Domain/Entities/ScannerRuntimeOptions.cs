using System;

namespace Platform.Domain.Entities;

public sealed record ScannerRuntimeOptions
{
    public double MaxCpuCores { get; init; } = 2.0;

    public long MaxMemoryBytes { get; init; } = 1_073_741_824; // 1 GiB

    public int MaxPids { get; init; } = 100;

    public long MaxScratchDiskBytes { get; init; } = 524_288_000; // 500 MiB

    public TimeSpan ExecutionTimeout { get; init; } = TimeSpan.FromMinutes(10);

    public bool EnableReadOnlyRoot { get; init; } = true;

    public bool DropAllCapabilities { get; init; } = true;

    public bool NoNewPrivileges { get; init; } = true;
}
