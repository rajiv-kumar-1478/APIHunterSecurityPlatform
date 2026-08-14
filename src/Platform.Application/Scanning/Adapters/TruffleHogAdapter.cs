using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Adapters;

/// <summary>
/// Universal scanner adapter for TruffleHog secret and live-credential detection engine (v3.96.0+).
/// Implements SPEC-008 adapter contract with immutable supply-chain provenance verified against GHCR.
/// </summary>
public sealed class TruffleHogAdapter : IScanToolAdapter
{
    private readonly TruffleHogOutputParser _parser;

    public ScanToolManifest Manifest { get; } = new(
        ToolKey: "trufflehog",
        Version: "3.96.0",
        Description: "TruffleHog credential and secret scanner for identifying leaked API keys and exposed credentials",
        ContainerImageRepository: "ghcr.io/trufflesecurity/trufflehog",
        ContainerImageReference: "ghcr.io/trufflesecurity/trufflehog:3.96.0",
        ContainerImageDigest: "sha256:b8acd9f7306d832b1f16e06003dac2283a737817954554111683ab7a56e9e539",
        SupportedProfiles: new HashSet<SecurityScanProfileType>
        {
            SecurityScanProfileType.Standard,
            SecurityScanProfileType.Deep
        },
        Capabilities: new HashSet<string>
        {
            "secret.scan",
            "credential.detection",
            "live.verification"
        },
        DiscoveredAssetTypes: new[]
        {
            "exposed_secret",
            "api_key",
            "credential"
        },
        ParserVersion: "1.0",
        ManifestVersion: "1.0",
        ExecutionPhase: ScannerExecutionPhase.StaticAnalysis
    );

    public TruffleHogAdapter(TruffleHogOutputParser parser)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
    }

    public ToolExecutionPlan PrepareExecution(ScanExecutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        bool allowLiveVerification = context.AdditionalOptions != null &&
            context.AdditionalOptions.TryGetValue("enable_live_verification", out var liveVal) &&
            string.Equals(liveVal, "true", StringComparison.OrdinalIgnoreCase);

        var args = new List<string>
        {
            "filesystem",
            ".",
            "--json",
            "--no-update",
            "--fail=false"
        };

        var allowedDestinations = new List<string>();

        if (!allowLiveVerification)
        {
            // Default fail-closed policy: disable outbound network verification requests unless explicitly authorized
            args.Add("--no-verification");
        }
        else
        {
            // Live verification authorized: populate provider endpoints
            if (context.AdditionalOptions != null &&
                context.AdditionalOptions.TryGetValue("verification_destinations", out var dests) &&
                !string.IsNullOrWhiteSpace(dests))
            {
                var split = dests.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                allowedDestinations.AddRange(split);
            }
            else
            {
                // Default authoritative verification provider endpoints
                allowedDestinations.Add("https://api.github.com");
                allowedDestinations.Add("https://api.slack.com");
                allowedDestinations.Add("https://api.stripe.com");
            }
        }

        if (context.Profile == SecurityScanProfileType.Deep)
        {
            args.Add("--archive-max-depth=5");
            args.Add("--archive-max-size=104857600");
        }

        var env = new Dictionary<string, string>
        {
            ["TRUFFLEHOG_NO_UPDATE"] = "true"
        };

        if (context.ProviderSecrets != null)
        {
            foreach (var kv in context.ProviderSecrets)
            {
                env[kv.Key] = kv.Value;
            }
        }

        var metadata = new Dictionary<string, string>
        {
            ["NetworkBehavior"] = allowLiveVerification ? "CredentialVerification" : "None",
            ["RequiresEgressAuthorization"] = allowLiveVerification ? "true" : "false"
        };

        return new ToolExecutionPlan(
            ToolKey: Manifest.ToolKey,
            Version: Manifest.Version,
            CommandLineArguments: args,
            EnvironmentVariables: env,
            AdditionalMetadata: metadata,
            AllowedVerificationDestinations: allowedDestinations.AsReadOnly()
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
