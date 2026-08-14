using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Adapters;

/// <summary>
/// SPEC-008 adapter for ProjectDiscovery httpx HTTP probing engine.
/// Wraps the proven Phase 8 HttpxOutputParser into the universal adapter contract.
/// </summary>
public sealed class HttpxAdapter : IScanToolAdapter
{
    private readonly HttpxOutputParser _parser;

    public ScanToolManifest Manifest { get; } = new(
        ToolKey: "httpx",
        Version: "1.6.0",
        Description: "ProjectDiscovery httpx HTTP probing and web technology detection engine",
        ContainerImageRepository: "ghcr.io/projectdiscovery/httpx",
        ContainerImageDigest: "sha256:52d58be716e8fe2a592da2a3a3652985d6c71c9b68a6f3dc8e4b789ad7e2c91b",
        SupportedProfiles: new HashSet<SecurityScanProfileType>
        {
            SecurityScanProfileType.Recon,
            SecurityScanProfileType.Standard,
            SecurityScanProfileType.Deep
        },
        Capabilities: new HashSet<string>
        {
            "http.probe",
            "tech.detect",
            "tls.inspect",
            "status.code"
        },
        DiscoveredAssetTypes: new[] { "endpoint", "tls_certificate", "web_technology" },
        ParserVersion: "1.0",
        ManifestVersion: "1.0"
    );

    public HttpxAdapter(HttpxOutputParser? parser = null)
    {
        _parser = parser ?? new HttpxOutputParser();
    }

    public ToolExecutionPlan PrepareExecution(ScanExecutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var args = new List<string>
        {
            "-u", context.TargetUrl,
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-follow-redirects"
        };

        var env = new Dictionary<string, string>();
        if (context.ProviderSecrets != null)
        {
            foreach (var kv in context.ProviderSecrets)
            {
                env[kv.Key] = kv.Value;
            }
        }

        return new ToolExecutionPlan(
            ToolKey: Manifest.ToolKey,
            Version: Manifest.Version,
            CommandLineArguments: args,
            EnvironmentVariables: env
        );
    }

    public Task<ToolParsedOutputResult> ParseOutputAsync(
        ScanExecutionContext context,
        ToolExecutionRawOutput rawOutput,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(rawOutput);

        if (string.IsNullOrWhiteSpace(rawOutput.StandardOutput))
        {
            return Task.FromResult(new ToolParsedOutputResult(
                Manifest.ToolKey,
                Manifest.Version,
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, false)
            ));
        }

        var jobContext = new ScanJobContext(
            JobId: context.ScanJobId,
            RepositoryId: Guid.Empty,
            TargetId: Guid.Empty,
            TargetUrl: context.TargetUrl,
            ScanProfile: context.Profile,
            JobStartedAtUtc: DateTime.UtcNow
        );

        var candidates = _parser.Parse(rawOutput.StandardOutput, jobContext);

        var endpointsCount = candidates.Count(c => !string.IsNullOrEmpty(c.EndpointPath) || !string.IsNullOrEmpty(c.TargetUrl));
        var coverage = new ScannerCoverage(
            EndpointsDiscovered: endpointsCount,
            ParametersExtracted: 0,
            AssetsProbed: candidates.Count > 0 ? 1 : 0,
            JavaScriptFilesDiscovered: 0,
            CoverageTruncated: false
        );

        return Task.FromResult(new ToolParsedOutputResult(
            Manifest.ToolKey,
            Manifest.Version,
            candidates,
            coverage
        ));
    }
}
