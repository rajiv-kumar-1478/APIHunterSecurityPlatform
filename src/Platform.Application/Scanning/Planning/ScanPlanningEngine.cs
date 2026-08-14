using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Planning;

/// <summary>
/// Authoritative capability-driven scan planning engine resolving dynamic tool sequences,
/// preference policies, prerequisite dependencies, and audit PlanHash.
/// </summary>
public sealed class ScanPlanningEngine : IScanPlanningEngine
{
    public const string CurrentPlannerVersion = "1.0.0";

    private readonly IScanToolRegistry _toolRegistry;
    private readonly ILogger<ScanPlanningEngine> _logger;

    public ScanPlanningEngine(
        IScanToolRegistry toolRegistry,
        ILogger<ScanPlanningEngine> logger)
    {
        _toolRegistry = toolRegistry ?? throw new ArgumentNullException(nameof(toolRegistry));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public ResolvedScanPlan PlanScan(ScanPlanningRequest request)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var disabledTools = request.DisabledToolKeys ?? new HashSet<string>();
        var matchingAdapters = _toolRegistry.GetAdaptersForProfile(request.Profile)
            .Where(a => !disabledTools.Contains(a.Manifest.ToolKey))
            .Where(a => ScanToolManifestValidator.Validate(a.Manifest).IsValid)
            .ToList();

        // 1. Filter by Target Asset Kind
        var candidateAdapters = FilterByTargetKind(matchingAdapters, request.TargetKind);

        // 2. Resolve Required Capabilities & Selection Policy
        var selectionPolicies = BuildPolicyLookup(request.CustomSelectionPolicies);
        var selectedAdapters = new List<IScanToolAdapter>();
        var selectionReasons = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var requiredCapabilities = request.RequiredCapabilities;
        if (requiredCapabilities == null || requiredCapabilities.Count == 0)
        {
            // Default: All applicable tools for this target kind and profile
            selectedAdapters.AddRange(candidateAdapters);
            foreach (var a in candidateAdapters)
            {
                selectionReasons[a.Manifest.ToolKey] = $"Matched target kind '{request.TargetKind}' and profile '{request.Profile}'.";
            }
        }
        else
        {
            // Resolve per capability using policy preferences
            foreach (var cap in requiredCapabilities)
            {
                var capableTools = candidateAdapters
                    .Where(a => a.Manifest.Capabilities.Contains(cap))
                    .ToList();

                if (capableTools.Count == 0)
                {
                    _logger.LogDebug("No available healthy tool provides capability '{Capability}' for target '{Target}'.",
                        cap, request.TargetUrl);
                    continue;
                }

                if (selectionPolicies.TryGetValue(cap, out var policy))
                {
                    // Preference order resolution
                    var ordered = capableTools
                        .OrderBy(t =>
                        {
                            var idx = policy.PreferredToolKeys.ToList().IndexOf(t.Manifest.ToolKey);
                            return idx >= 0 ? idx : int.MaxValue;
                        })
                        .Take(policy.AllowMultipleTools ? policy.MaxTools : 1)
                        .ToList();

                    foreach (var chosen in ordered)
                    {
                        if (!selectedAdapters.Contains(chosen))
                        {
                            selectedAdapters.Add(chosen);
                            selectionReasons[chosen.Manifest.ToolKey] = $"Preferred provider for capability '{cap}' via selection policy.";
                        }
                    }
                }
                else
                {
                    var chosen = capableTools[0];
                    if (!selectedAdapters.Contains(chosen))
                    {
                        selectedAdapters.Add(chosen);
                        selectionReasons[chosen.Manifest.ToolKey] = $"Selected for capability '{cap}'.";
                    }
                }
            }
        }

        // 3. Capability-based Phase Sequencing & Dependency Ordering
        var sequencedInvocations = SequenceInvocations(selectedAdapters, selectionReasons);

        // 4. Extract Rule Set Versions
        var ruleSetVersions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var inv in sequencedInvocations)
        {
            ruleSetVersions[inv.ToolKey] = inv.Version;
        }

        var executionSequence = sequencedInvocations.Select(i => i.ToolKey).ToList();

        // 5. Generate Audit PlanHash
        var planHash = ComputePlanHash(request.ScanJobId, request.TargetKind, request.Profile, executionSequence, CurrentPlannerVersion);

        _logger.LogInformation("Resolved scan plan for Job '{JobId}': {Count} tools selected ({Sequence}) with PlanHash '{Hash}'.",
            request.ScanJobId, sequencedInvocations.Count, string.Join(" -> ", executionSequence), planHash);

        return new ResolvedScanPlan(
            ScanJobId: request.ScanJobId,
            TenantId: request.TenantId,
            TargetKind: request.TargetKind,
            Profile: request.Profile,
            PlannedInvocations: sequencedInvocations.AsReadOnly(),
            ExecutionSequence: executionSequence.AsReadOnly(),
            RuleSetVersions: ruleSetVersions,
            SelectionReasons: selectionReasons,
            PlannerVersion: CurrentPlannerVersion,
            PlanHash: planHash,
            PlannedAtUtc: DateTime.UtcNow,
            TargetUrl: request.TargetUrl
        );
    }

    private static List<IScanToolAdapter> FilterByTargetKind(
        List<IScanToolAdapter> adapters,
        TargetAssetKind targetKind)
    {
        return targetKind switch
        {
            TargetAssetKind.WebEndpoint => adapters.Where(a =>
                a.Manifest.Capabilities.Any(c => c is "http.probe" or "template.vulnerability" or "cve.detect" or "dast.scan" or "api.fuzz")).ToList(),

            TargetAssetKind.Domain => adapters.Where(a =>
                a.Manifest.Capabilities.Any(c => c is "subdomain.enumerate" or "dns.resolve" or "http.probe")).ToList(),

            TargetAssetKind.SourceRepository => adapters.Where(a =>
                a.Manifest.Capabilities.Any(c => c is "sast.scan" or "code.vulnerability" or "secret.deep_scan" or "config.audit")).ToList(),

            TargetAssetKind.JavaScriptBundle => adapters.Where(a =>
                a.Manifest.Capabilities.Any(c => c is "js.crawl" or "endpoint.extract" or "secret.detect" or "domxss.detect")).ToList(),

            TargetAssetKind.ApiContract => adapters.Where(a =>
                a.Manifest.Capabilities.Any(c => c is "api.fuzz" or "bola.verify" or "tamper.verify" or "graphql.verify")).ToList(),

            _ => adapters
        };
    }

    private static Dictionary<string, ScannerSelectionPolicy> BuildPolicyLookup(
        IReadOnlyList<ScannerSelectionPolicy>? customPolicies)
    {
        var lookup = new Dictionary<string, ScannerSelectionPolicy>(StringComparer.OrdinalIgnoreCase);

        // Default platform selection policies
        lookup["sast.scan"] = new ScannerSelectionPolicy("sast.scan", new[] { "semgrep" }, AllowMultipleTools: false);
        lookup["api.fuzz"] = new ScannerSelectionPolicy("api.fuzz", new[] { "bughunter" }, AllowMultipleTools: false);
        lookup["js.crawl"] = new ScannerSelectionPolicy("js.crawl", new[] { "jsminer" }, AllowMultipleTools: false);
        lookup["template.vulnerability"] = new ScannerSelectionPolicy("template.vulnerability", new[] { "nuclei" }, AllowMultipleTools: false);
        lookup["http.probe"] = new ScannerSelectionPolicy("http.probe", new[] { "httpx" }, AllowMultipleTools: false);
        lookup["subdomain.enumerate"] = new ScannerSelectionPolicy("subdomain.enumerate", new[] { "subfinder" }, AllowMultipleTools: false);

        if (customPolicies != null)
        {
            foreach (var p in customPolicies)
            {
                lookup[p.Capability] = p;
            }
        }

        return lookup;
    }

    private static List<PlannedToolInvocation> SequenceInvocations(
        List<IScanToolAdapter> adapters,
        Dictionary<string, string> selectionReasons)
    {
        // Sort by Execution Phase (Discovery -> StaticAnalysis -> AttackSurfaceAnalysis -> ActiveVerification)
        var sorted = adapters
            .OrderBy(a => (int)a.Manifest.ExecutionPhase)
            .ThenBy(a => a.Manifest.ToolKey, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var result = new List<PlannedToolInvocation>();

        foreach (var a in sorted)
        {
            var manifest = a.Manifest;
            selectionReasons.TryGetValue(manifest.ToolKey, out var reason);

            result.Add(new PlannedToolInvocation(
                ToolKey: manifest.ToolKey,
                Version: manifest.Version,
                Phase: manifest.ExecutionPhase,
                SatisfiedCapabilities: manifest.Capabilities.ToList().AsReadOnly(),
                RequiredPrerequisiteCapabilities: manifest.RequiredCapabilities ?? Array.Empty<string>(),
                SelectionReason: reason ?? "Standard capability mapping."
            ));
        }

        return result;
    }

    public static string ComputePlanHash(
        Guid scanJobId,
        TargetAssetKind targetKind,
        SecurityScanProfileType profile,
        IReadOnlyList<string> sequence,
        string plannerVersion)
    {
        var input = $"{scanJobId}:{targetKind}:{profile}:{string.Join(",", sequence)}:{plannerVersion}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
