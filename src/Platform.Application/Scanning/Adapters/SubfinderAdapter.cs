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
/// SPEC-008 adapter for ProjectDiscovery Subfinder subdomain enumeration engine.
/// Wraps the proven Phase 8 SubfinderOutputParser into the universal adapter contract.
/// </summary>
public sealed class SubfinderAdapter : IScanToolAdapter
{
    private readonly SubfinderOutputParser _parser;

    public ScanToolManifest Manifest { get; } = new(
        ToolKey: "subfinder",
        Version: "2.6.5",
        Description: "ProjectDiscovery Subfinder fast passive subdomain enumeration engine",
        ContainerImageRepository: "ghcr.io/projectdiscovery/subfinder",
        ContainerImageDigest: "sha256:5a9e3d937013e8e2d424b94f1c1f4e5a9c40212f0e0f8f9024f0c430e764a59b",
        SupportedProfiles: new HashSet<SecurityScanProfileType>
        {
            SecurityScanProfileType.Recon,
            SecurityScanProfileType.Standard,
            SecurityScanProfileType.Deep
        },
        Capabilities: new HashSet<string>
        {
            "subdomain.enumeration",
            "passive.dns",
            "asset.discovery"
        },
        DiscoveredAssetTypes: new[] { "subdomain", "fqdn" },
        ParserVersion: "1.0",
        ManifestVersion: "1.0"
    );

    public SubfinderAdapter(SubfinderOutputParser? parser = null)
    {
        _parser = parser ?? new SubfinderOutputParser();
    }

    public ToolExecutionPlan PrepareExecution(ScanExecutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var domain = ExtractDomain(context.TargetUrl);

        var args = new List<string>
        {
            "-d", domain,
            "-json",
            "-silent",
            "-all"
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

        var subdomainsCount = candidates.Count;
        var coverage = new ScannerCoverage(
            EndpointsDiscovered: 0,
            ParametersExtracted: 0,
            AssetsProbed: subdomainsCount,
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

    private static string ExtractDomain(string rawUrl)
    {
        if (string.IsNullOrWhiteSpace(rawUrl)) return string.Empty;

        if (Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }

        return rawUrl.Replace("http://", "").Replace("https://", "").Split('/')[0];
    }
}
