using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Common;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Dedicated orchestration engine responsible for scan profile planning, tool capability evaluation,
/// phased sandboxed execution, output parsing, finding ingestion, and execution receipt aggregation.
/// </summary>
public class ScanExecutionOrchestrator
{
    private readonly ScanToolRegistryService _toolRegistry;
    private readonly IToolOutputParserProvider _parserProvider;
    private readonly ScanFindingIngestionEngine _ingestionEngine;
    private readonly ILogger<ScanExecutionOrchestrator> _logger;

    public ScanExecutionOrchestrator(
        ScanToolRegistryService toolRegistry,
        IToolOutputParserProvider parserProvider,
        ScanFindingIngestionEngine ingestionEngine,
        ILogger<ScanExecutionOrchestrator> logger)
    {
        _toolRegistry = toolRegistry ?? throw new ArgumentNullException(nameof(toolRegistry));
        _parserProvider = parserProvider ?? throw new ArgumentNullException(nameof(parserProvider));
        _ingestionEngine = ingestionEngine ?? throw new ArgumentNullException(nameof(ingestionEngine));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Executes the multi-tool scan pipeline for a scan job across explicit phases.
    /// </summary>
    public async Task<ScanExecutionReceipt> ExecutePipelineAsync(
        SecurityScanJob job,
        EgressTarget egressTarget,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        IScannerRuntimeSandbox runtimeSandbox,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(egressTarget);
        ArgumentNullException.ThrowIfNull(secretLease);
        ArgumentNullException.ThrowIfNull(runtimeSandbox);

        var startedAtUtc = DateTime.UtcNow;
        var canonicalProfile = ScanProfileMatrix.CanonicalizeProfile(job.ScanProfile);

        _logger.LogInformation("Orchestrator planning scan job '{JobId}' for canonical profile '{Profile}'.", job.Id, canonicalProfile);

        // 1. Fetch Authorized Manifest Map
        var authorizedManifestMap = await _toolRegistry.GetAuthorizedManifestMapAsync(ct);

        // 2. Resolve Profile Definition and Required Capabilities
        var profileDef = ScanProfileMatrix.GetProfileDefinition(canonicalProfile);
        var requiredCapabilities = profileDef.RequiredCapabilities.ToHashSet();

        // 3. Fetch Tools and Filter for Health and Required Capability Match
        var candidateTools = await _toolRegistry.GetToolsForCapabilitiesAsync(requiredCapabilities, ct);
        var eligibleToolsWithPhases = new List<(ScanToolDto Tool, ScanExecutionPhase Phase)>();

        foreach (var tool in candidateTools)
        {
            if (!tool.Enabled)
            {
                _logger.LogDebug("Tool '{ToolKey}' is disabled; skipping.", tool.ToolKey);
                continue;
            }

            if (tool.HealthStatus != ToolHealthStatus.Healthy)
            {
                _logger.LogWarning("Tool '{ToolKey}' is unhealthy ({Status}); skipping.", tool.ToolKey, tool.HealthStatus);
                continue;
            }

            var toolCapabilities = tool.Capabilities
                .Select(c => Enum.TryParse<ToolCapability>(c, true, out var parsed) ? parsed : (ToolCapability?)null)
                .Where(c => c.HasValue)
                .Select(c => c!.Value)
                .ToList();

            if (toolCapabilities.Any(c => requiredCapabilities.Contains(c)))
            {
                var phase = DetermineToolPhase(toolCapabilities);
                eligibleToolsWithPhases.Add((tool, phase));
                _logger.LogInformation("Tool '{ToolKey}' is eligible for profile '{Profile}' (Phase: {Phase}).", tool.ToolKey, canonicalProfile, phase);
            }
        }

        // Fail-Closed: If no compatible tools are available
        if (eligibleToolsWithPhases.Count == 0)
        {
            _logger.LogError("No compatible and healthy tools found for profile '{Profile}' in job '{JobId}'.", canonicalProfile, job.Id);
            return new ScanExecutionReceipt(
                JobId: job.Id,
                Profile: canonicalProfile,
                FinalJobStatus: SecurityScanJobStatus.Failed,
                StartedAtUtc: startedAtUtc,
                CompletedAtUtc: DateTime.UtcNow,
                ToolReceipts: Array.Empty<ToolExecutionReceipt>(),
                TotalFindingsCreated: 0,
                TotalFindingsUpdated: 0,
                Summary: "NO_COMPATIBLE_TOOLS_AVAILABLE"
            );
        }

        // 4. Order Tools by Explicit Execution Phases (Discovery -> Probing -> Assessment)
        var orderedPlan = eligibleToolsWithPhases
            .OrderBy(t => (int)t.Phase)
            .ThenBy(t => t.Tool.DisplayName)
            .ToList();

        var toolReceipts = new List<ToolExecutionReceipt>();
        var totalFindingsCreated = 0;
        var totalFindingsUpdated = 0;
        var jobContext = new ScanJobContext(job.Id, job.RepositoryId ?? Guid.Empty, job.TargetId ?? Guid.Empty, job.TargetUrl, canonicalProfile, startedAtUtc);

        var successfulToolsCount = 0;
        var failedToolsCount = 0;
        var fatalSecurityBoundaryFailure = false;

        // 5. Sequential Phase Execution
        foreach (var (tool, phase) in orderedPlan)
        {
            ct.ThrowIfCancellationRequested();

            if (fatalSecurityBoundaryFailure)
            {
                _logger.LogWarning("Skipping remaining tool '{ToolKey}' due to prior fatal sandbox/security boundary failure.", tool.ToolKey);
                toolReceipts.Add(new ToolExecutionReceipt(
                    ToolKey: tool.ToolKey,
                    Version: tool.Version,
                    Executable: tool.Executable,
                    ContainerImageRepository: tool.ContainerImageRepository,
                    ContainerImageDigest: tool.ContainerImageDigest,
                    Profile: canonicalProfile,
                    Phase: phase,
                    Status: ToolExecutionStatus.Skipped,
                    StartedAtUtc: DateTime.UtcNow,
                    CompletedAtUtc: DateTime.UtcNow,
                    DurationMs: 0,
                    OutputSizeBytes: 0,
                    CandidatesParsed: 0,
                    FindingsCreated: 0,
                    FindingsUpdated: 0,
                    FailureReason: "SKIPPED_DUE_TO_FATAL_SECURITY_BOUNDARY_FAILURE"
                ));
                continue;
            }

            _logger.LogInformation("Orchestrator executing Phase {Phase} tool '{ToolKey}' ({DisplayName}) for job '{JobId}'.", phase, tool.ToolKey, tool.DisplayName, job.Id);

            var toolStartedAtUtc = DateTime.UtcNow;
            var sw = Stopwatch.StartNew();

            var toolArgs = new Dictionary<string, string>();
            if (job.TargetUrl.StartsWith("-"))
            {
                toolArgs[job.TargetUrl] = string.Empty;
            }
            else if (string.Equals(job.TargetUrl, "version", StringComparison.OrdinalIgnoreCase))
            {
                toolArgs["--version"] = string.Empty;
            }
            else
            {
                toolArgs["target"] = job.TargetUrl;
            }

            var toolRequest = new ToolExecutionRequest(
                ToolKey: tool.ToolKey,
                Version: tool.Version,
                Arguments: toolArgs,
                ScanJobId: job.Id,
                Timeout: TimeSpan.FromMinutes(10),
                Executable: tool.Executable,
                ContainerImageRepository: tool.ContainerImageRepository,
                ContainerImageDigest: tool.ContainerImageDigest,
                AuthorizedManifest: authorizedManifestMap
            );

            ToolExecutionResult toolResult;
            try
            {
                toolResult = await runtimeSandbox.ExecuteInSandboxAsync(toolRequest, egressTarget, secretLease, scratchDirectory, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected sandbox execution crash for tool '{ToolKey}' in job '{JobId}'.", tool.ToolKey, job.Id);
                fatalSecurityBoundaryFailure = true;
                toolResult = new ToolExecutionResult(
                    ToolKey: tool.ToolKey,
                    Version: tool.Version,
                    Status: ToolExecutionStatus.Failed,
                    ExitCode: -1,
                    ArtifactReference: null,
                    ErrorCode: $"SANDBOX_EXECUTION_CRASH: {ex.Message}"
                );
            }
            sw.Stop();
            var toolCompletedAtUtc = DateTime.UtcNow;

            var rawOutput = ResolveToolOutput(toolResult, scratchDirectory);
            var outputBytes = (long)(rawOutput?.Length ?? 0);
            var candidatesParsed = 0;
            var toolFindingsCreated = 0;
            var toolFindingsUpdated = 0;
            string? failureReason = null;

            if (toolResult.Status == ToolExecutionStatus.Success)
            {
                successfulToolsCount++;

                // 6. Tool Output Parsing & Finding Ingestion with Immutable Provenance
                if (!string.IsNullOrWhiteSpace(rawOutput))
                {
                    if (_parserProvider.TryGetParser(tool.ToolKey, out var parser))
                    {
                        var candidates = parser.Parse(rawOutput, jobContext);
                        candidatesParsed = candidates.Count;

                        if (candidatesParsed > 0)
                        {
                            var candidatesWithProvenance = candidates.Select(c => c with
                            {
                                ContainerImageRepository = tool.ContainerImageRepository,
                                ContainerImageDigest = tool.ContainerImageDigest,
                                Executable = tool.Executable
                            }).ToList();

                            var ingestionResult = await _ingestionEngine.IngestCandidatesAsync(candidatesWithProvenance, jobContext, null, ct);
                            toolFindingsCreated = ingestionResult.NewFindingsCreated;
                            toolFindingsUpdated = ingestionResult.ExistingFindingsUpdated;
                            totalFindingsCreated += toolFindingsCreated;
                            totalFindingsUpdated += toolFindingsUpdated;

                            _logger.LogInformation("Tool '{ToolKey}' produced {Candidates} candidate(s) -> {Created} new, {Updated} updated findings.",
                                tool.ToolKey, candidatesParsed, toolFindingsCreated, toolFindingsUpdated);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("No registered output parser found for tool '{ToolKey}'. Output ingestion skipped.", tool.ToolKey);
                    }
                }
            }
            else
            {
                failedToolsCount++;
                failureReason = toolResult.ErrorCode ?? "TOOL_EXECUTION_FAILED";
                _logger.LogWarning("Tool '{ToolKey}' execution failed ({Status}): {Reason}", tool.ToolKey, toolResult.Status, failureReason);

                if (failureReason.StartsWith("SANDBOX_") || failureReason.StartsWith("SECURITY_"))
                {
                    fatalSecurityBoundaryFailure = true;
                }
            }

            var receipt = new ToolExecutionReceipt(
                ToolKey: tool.ToolKey,
                Version: tool.Version,
                Executable: tool.Executable,
                ContainerImageRepository: tool.ContainerImageRepository,
                ContainerImageDigest: tool.ContainerImageDigest,
                Profile: canonicalProfile,
                Phase: phase,
                Status: toolResult.Status,
                StartedAtUtc: toolStartedAtUtc,
                CompletedAtUtc: toolCompletedAtUtc,
                DurationMs: sw.ElapsedMilliseconds,
                OutputSizeBytes: outputBytes,
                CandidatesParsed: candidatesParsed,
                FindingsCreated: toolFindingsCreated,
                FindingsUpdated: toolFindingsUpdated,
                FailureReason: failureReason
            );

            toolReceipts.Add(receipt);
        }

        // 7. Multi-Tool Failure Semantics & Final Job Status Calculation
        SecurityScanJobStatus finalStatus;
        string summary;

        if (failedToolsCount == 0 && successfulToolsCount > 0)
        {
            finalStatus = SecurityScanJobStatus.Completed;
            summary = $"Scan completed successfully. All {successfulToolsCount} tool(s) executed. Findings created: {totalFindingsCreated}, updated: {totalFindingsUpdated}.";
        }
        else if (successfulToolsCount > 0 && failedToolsCount > 0)
        {
            finalStatus = SecurityScanJobStatus.CompletedWithWarnings;
            summary = $"Scan completed with warnings: {successfulToolsCount} tool(s) succeeded, {failedToolsCount} tool(s) failed. Findings created: {totalFindingsCreated}, updated: {totalFindingsUpdated}.";
        }
        else
        {
            finalStatus = SecurityScanJobStatus.Failed;
            summary = $"All {failedToolsCount} tool(s) failed execution.";
        }

        _logger.LogInformation("Scan job '{JobId}' finished with status '{Status}'. Summary: {Summary}", job.Id, finalStatus, summary);

        return new ScanExecutionReceipt(
            JobId: job.Id,
            Profile: canonicalProfile,
            FinalJobStatus: finalStatus,
            StartedAtUtc: startedAtUtc,
            CompletedAtUtc: DateTime.UtcNow,
            ToolReceipts: toolReceipts,
            TotalFindingsCreated: totalFindingsCreated,
            TotalFindingsUpdated: totalFindingsUpdated,
            Summary: summary
        );
    }

    private static string? ResolveToolOutput(ToolExecutionResult toolResult, string scratchDirectory)
    {
        if (toolResult.ArtifactReference != null)
        {
            if (File.Exists(toolResult.ArtifactReference))
            {
                try
                {
                    return File.ReadAllText(toolResult.ArtifactReference);
                }
                catch
                {
                    // Fallback
                }
            }

            // Direct in-memory string artifact
            if (toolResult.ArtifactReference.TrimStart().StartsWith("{") || toolResult.ArtifactReference.TrimStart().StartsWith("["))
            {
                return toolResult.ArtifactReference;
            }
        }

        var defaultArtifactFile = Path.Combine(scratchDirectory, $"{toolResult.ToolKey}_output.json");
        if (File.Exists(defaultArtifactFile))
        {
            try
            {
                return File.ReadAllText(defaultArtifactFile);
            }
            catch
            {
                // Ignore file read error
            }
        }

        return null;
    }

    private static ScanExecutionPhase DetermineToolPhase(IReadOnlyList<ToolCapability> capabilities)
    {
        if (capabilities.Contains(ToolCapability.VulnerabilityScanning) ||
            capabilities.Contains(ToolCapability.UrlCrawling) ||
            capabilities.Contains(ToolCapability.Fuzzing) ||
            capabilities.Contains(ToolCapability.AiAssistedHunting) ||
            capabilities.Contains(ToolCapability.ReportGeneration))
        {
            return ScanExecutionPhase.Assessment;
        }

        if (capabilities.Contains(ToolCapability.HttpProbing) ||
            capabilities.Contains(ToolCapability.DnsResolution))
        {
            return ScanExecutionPhase.Probing;
        }

        return ScanExecutionPhase.Discovery;
    }
}
