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
/// SPEC-008 adapter for ProjectDiscovery Nuclei vulnerability scanner.
/// Wraps the proven Phase 8 NucleiOutputParser into the universal adapter contract.
/// </summary>
public sealed class NucleiAdapter : IScanToolAdapter
{
    private readonly NucleiOutputParser _parser;

    public ScanToolManifest Manifest { get; } = new(
        ToolKey: "nuclei",
        Version: "3.2.0",
        Description: "ProjectDiscovery Nuclei template-based vulnerability assessment scanner",
        ContainerImageRepository: "ghcr.io/projectdiscovery/nuclei",
        ContainerImageDigest: "sha256:1a85e13b8279930f796de14187063d80b721e7d8001fb1e204c35e39d5628bbf",
        SupportedProfiles: new HashSet<SecurityScanProfileType>
        {
            SecurityScanProfileType.Standard,
            SecurityScanProfileType.Deep
        },
        Capabilities: new HashSet<string>
        {
            "vulnerability.scan",
            "cve.detect",
            "misconfig.detect",
            "exposure.detect"
        },
        DiscoveredAssetTypes: new[] { "vulnerability", "cve", "misconfiguration" },
        ParserVersion: "1.0",
        ManifestVersion: "1.0"
    );

    public NucleiAdapter(NucleiOutputParser? parser = null)
    {
        _parser = parser ?? new NucleiOutputParser();
    }

    public ToolExecutionPlan PrepareExecution(ScanExecutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var args = new List<string>
        {
            "-u", context.TargetUrl,
            "-jsonl",
            "-silent",
            "-duc",
            "-no-interactsh",
            "-tags", "cve,misconfig,exposure,token,auth"
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

        var coverage = new ScannerCoverage(
            EndpointsDiscovered: candidates.Select(c => c.EndpointPath).Where(p => !string.IsNullOrEmpty(p)).Distinct().Count(),
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
