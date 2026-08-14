using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Adapters;

/// <summary>
/// SPEC-008.3 Universal Scanner Adapter for JsMiner JavaScript crawler, endpoint/parameter extractor,
/// unvalidated secret candidate detector, and DOM XSS dataflow analyzer.
/// </summary>
public sealed class JsMinerAdapter : IScanToolAdapter
{
    private readonly JsMinerOutputParser _parser;

    public ScanToolManifest Manifest { get; } = new(
        ToolKey: "jsminer",
        Version: "1.2.0",
        Description: "APIHunter JavaScript security crawler, endpoint extraction, secret detection, and DOM XSS analysis engine",
        ContainerImageRepository: "ghcr.io/apihunter-security/jsminer",
        ContainerImageReference: "ghcr.io/apihunter-security/jsminer:v1.2.0",
        ContainerImageDigest: "sha256:d8246a482b9a7beebcae7cb9be9c1fe0d421884bb07c11f422bce37b56ff1ec8",
        SupportedProfiles: new HashSet<SecurityScanProfileType>
        {
            SecurityScanProfileType.Standard,
            SecurityScanProfileType.Deep
        },
        Capabilities: new HashSet<string>
        {
            "js.crawl",
            "endpoint.extract",
            "parameter.extract",
            "secret.detect",
            "domxss.detect"
        },
        DiscoveredAssetTypes: new[]
        {
            "javascript_file",
            "api_endpoint",
            "parameter",
            "unvalidated_secret",
            "dom_xss_sink"
        },
        ParserVersion: "1.0",
        ManifestVersion: "1.0"
    );

    public JsMinerAdapter(JsMinerOutputParser parser)
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
            "-silent",
            "-depth", context.Profile == SecurityScanProfileType.Deep ? "5" : "3",
            "-extract-endpoints",
            "-extract-params",
            "-extract-secrets",
            "-detect-domxss"
        };

        var env = new Dictionary<string, string>
        {
            ["JSMINER_OUTPUT_FORMAT"] = "jsonl",
            ["JSMINER_MAX_DEPTH"] = context.Profile == SecurityScanProfileType.Deep ? "5" : "3"
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
