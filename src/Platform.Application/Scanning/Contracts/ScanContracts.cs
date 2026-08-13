using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

public record ScanExecutionRequest(
    Guid ScanJobId,
    string TargetUrl,
    SecurityScanProfileType Profile,
    string ProviderKey,
    IReadOnlyDictionary<string, string> Parameters,
    TimeSpan Timeout
);

public record ScanExecutionResult(
    Guid ScanJobId,
    SecurityScanJobStatus Status,
    string? ExternalScanId,
    string? ArtifactReference,
    string? FailureReason,
    DateTime CompletedAtUtc
);

public record ScanStartResult(
    bool Success,
    string ExternalScanId,
    string? ErrorMessage
);

public record ScanStatusResult(
    string ExternalScanId,
    SecurityScanJobStatus Status,
    int ProgressPercent,
    string? Message
);

public record ScanResult(
    string ExternalScanId,
    SecurityScanJobStatus Status,
    IReadOnlyList<ToolExecutionResult> ToolResults,
    string? ArtifactReference,
    string? Summary
);

public record ToolExecutionRequest(
    string ToolKey,
    string Version,
    IReadOnlyDictionary<string, string> Arguments,
    Guid ScanJobId,
    TimeSpan Timeout,
    string? Executable = null,
    IReadOnlyDictionary<string, string>? AuthorizedManifest = null
);

public record ToolExecutionResult(
    string ToolKey,
    string Version,
    ToolExecutionStatus Status,
    int ExitCode,
    string? ArtifactReference,
    string? ErrorCode
);

public record ProviderSecretStatus(
    string ProviderKey,
    bool Configured,
    IReadOnlyList<string> RequiredKeys,
    IReadOnlyList<string> OptionalKeys,
    DateTime? LastValidatedAtUtc
);

public sealed class ProviderSecretLease : IDisposable
{
    private readonly Dictionary<string, string> _secrets;
    private bool _disposed;

    public string ProviderKey { get; }
    public IReadOnlyDictionary<string, string> Secrets => _disposed ? new Dictionary<string, string>() : _secrets;
    public DateTime ExpiresAtUtc { get; }

    public ProviderSecretLease(string providerKey, IDictionary<string, string> secrets, TimeSpan duration)
    {
        ProviderKey = providerKey;
        _secrets = new Dictionary<string, string>(secrets, StringComparer.OrdinalIgnoreCase);
        ExpiresAtUtc = DateTime.UtcNow.Add(duration);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _secrets.Clear();
            _disposed = true;
        }
    }
}

public record ProviderCredentialDefinition(
    string ProviderKey,
    string CredentialName,
    bool Required,
    string ConsumerTool
);

public record ScanCapabilityDto(
    string CapabilityKey,
    string DisplayName,
    string Description,
    IReadOnlyList<string> AvailableTools
);

public record ScanToolDto(
    Guid Id,
    string ToolKey,
    string DisplayName,
    string Version,
    string Executable,
    bool Enabled,
    bool Required,
    IReadOnlyList<string> Capabilities,
    ToolHealthStatus HealthStatus,
    DateTime? LastHealthCheckUtc
);

public record ScanProviderDto(
    string ProviderKey,
    string DisplayName,
    bool Enabled,
    IReadOnlyList<string> SupportedCapabilities,
    IReadOnlyList<string> RequiredTools
);

public record CreateScanJobRequest(
    Guid? RepositoryId,
    Guid? TargetId,
    string TargetUrl,
    SecurityScanProfileType ScanProfile = SecurityScanProfileType.Recon,
    string ProviderKey = "bughunter"
);

public sealed record EgressTarget(
    string RawTargetUrl,
    string CanonicalHost,
    int Port,
    string Scheme,
    IReadOnlySet<System.Net.IPAddress> ApprovedIpAddresses,
    DateTime ResolvedAtUtc,
    DateTime ExpiresAtUtc,
    string PolicyVersion
)
{
    public bool IsExpired(DateTime? nowUtc = null) => (nowUtc ?? DateTime.UtcNow) >= ExpiresAtUtc;
}

public record ToolProbeResult(
    string ToolKey,
    bool Success,
    string ProbeName,
    string? ErrorCode,
    string? ErrorMessage,
    DateTime ProbedAtUtc
);

public record ProvisioningResult(
    string ToolKey,
    string Version,
    bool Success,
    string InstallPath,
    string? ErrorCode,
    string? ErrorMessage
);
