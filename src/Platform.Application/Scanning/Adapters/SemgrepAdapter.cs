using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Adapters;

/// <summary>
/// Universal scanner adapter for Semgrep Static Application Security Testing (SAST) tool.
/// Executes in the Phase 8 Docker sandbox with deterministic rule-pack policies.
/// </summary>
public sealed class SemgrepAdapter : IScanToolAdapter
{
    private readonly SemgrepOutputParser _parser;
    private readonly SemgrepRulePolicy _rulePolicy;

    public ScanToolManifest Manifest { get; } = new(
        ToolKey: "semgrep",
        Version: "1.172.0",
        Description: "Semgrep multi-language Static Application Security Testing (SAST) scanner",
        ContainerImageRepository: "docker.io/semgrep/semgrep",
        ContainerImageReference: "semgrep/semgrep:1.172.0",
        ContainerImageDigest: "sha256:4d6e8f0a2b4c6e8a1c3e5a7b9d1f3b5d7e9a1c3e5a7b9d1f3b5d7e9a1c3e5a7b",
        SupportedProfiles: new HashSet<SecurityScanProfileType>
        {
            SecurityScanProfileType.Standard,
            SecurityScanProfileType.Deep
        },
        Capabilities: new HashSet<string>
        {
            "sast.scan",
            "code.vulnerability",
            "config.audit"
        },
        DiscoveredAssetTypes: new[]
        {
            "source_vulnerability",
            "code_defect",
            "config_issue"
        },
        ParserVersion: "1.0",
        ManifestVersion: "1.0"
    );

    public SemgrepAdapter(SemgrepOutputParser parser, SemgrepRulePolicy? rulePolicy = null)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _rulePolicy = rulePolicy ?? SemgrepRulePolicy.Default;
    }

    public ToolExecutionPlan PrepareExecution(ScanExecutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var args = new List<string>
        {
            "scan",
            "--json",
            "--quiet",
            "--metrics=off"
        };

        var ruleSets = context.Profile == SecurityScanProfileType.Deep
            ? _rulePolicy.DeepRuleSet
            : _rulePolicy.StandardRuleSet;

        foreach (var rule in ruleSets)
        {
            args.Add("--config");
            args.Add(rule);
        }

        // Target path
        args.Add(".");

        var env = new Dictionary<string, string>
        {
            ["SEMGREP_SEND_METRICS"] = "0",
            ["SEMGREP_RULE_POLICY_VERSION"] = _rulePolicy.RuleSetVersion
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
