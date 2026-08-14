using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Adapters;

/// <summary>
/// Universal scanner adapter for BugHunter API contract, BOLA, and authorization verification tool.
/// Executes in the Phase 8 Docker sandbox without modifying the Phase 9 campaign scheduler.
/// </summary>
public sealed class BugHunterAdapter : IScanToolAdapter
{
    private readonly BugHunterOutputParser _parser;

    public ScanToolManifest Manifest { get; } = new(
        ToolKey: "bughunter",
        Version: "2.1.0",
        Description: "APIHunter BugHunter active contract, BOLA, and authorization verification scanner",
        ContainerImageRepository: "ghcr.io/apihunter-security/bughunter",
        ContainerImageReference: "ghcr.io/apihunter-security/bughunter:v2.1.0",
        ContainerImageDigest: "sha256:7c9e1a2b3c4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
        SupportedProfiles: new HashSet<SecurityScanProfileType>
        {
            SecurityScanProfileType.Standard,
            SecurityScanProfileType.Deep
        },
        Capabilities: new HashSet<string>
        {
            "api.fuzz",
            "bola.verify",
            "tamper.verify",
            "graphql.verify"
        },
        DiscoveredAssetTypes: new[]
        {
            "api_vulnerability",
            "bola_defect",
            "parameter_tampering"
        },
        ParserVersion: "1.0",
        ManifestVersion: "1.0",
        ExecutionPhase: Planning.Contracts.ScannerExecutionPhase.ActiveVerification,
        RequiredCapabilities: new[] { "endpoint.extract" }
    );

    public BugHunterAdapter(BugHunterOutputParser parser)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
    }

    public ToolExecutionPlan PrepareExecution(ScanExecutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var args = new List<string>
        {
            "-u", context.TargetUrl,
            "-json",
            "-silent"
        };

        if (context.Profile == SecurityScanProfileType.Deep)
        {
            args.Add("-concurrency");
            args.Add("5");
            args.Add("-verify-bola");
            args.Add("-verify-tamper");
            args.Add("-verify-contract");
            args.Add("-verify-graphql");
        }
        else
        {
            args.Add("-concurrency");
            args.Add("2");
            args.Add("-verify-bola");
            args.Add("-verify-tamper");
        }

        var env = new Dictionary<string, string>
        {
            ["BUGHUNTER_OUTPUT_FORMAT"] = "jsonl",
            ["BUGHUNTER_SILENT"] = "true"
        };

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

    public async Task<ToolParsedOutputResult> ParseOutputAsync(
        ScanExecutionContext context,
        ToolExecutionRawOutput rawOutput,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(rawOutput);

        return await _parser.ParseAsync(context, rawOutput, ct);
    }
}
