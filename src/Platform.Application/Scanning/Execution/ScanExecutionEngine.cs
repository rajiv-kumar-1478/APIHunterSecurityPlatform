using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Execution.Contracts;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Application.Scanning.Validation;
using Platform.Application.Services;
using Platform.Domain.Entities;

namespace Platform.Application.Scanning.Execution;

/// <summary>
/// Authoritative scanner execution engine managing sandbox execution, timeout guards,
/// resource isolation, per-tool invocation state, candidate ingestion, and execution read models.
/// </summary>
public sealed class ScanExecutionEngine : IScanExecutionEngine
{
    public static readonly TimeSpan DefaultPerToolTimeout = TimeSpan.FromSeconds(300);

    private readonly IScanToolRegistry _toolRegistry;
    private readonly IPlatformDbContext _dbContext;
    private readonly IScannerRuntimeSandbox? _runtimeSandbox;
    private readonly ScanFindingIngestionEngine? _ingestionEngine;
    private readonly IEgressPolicyEngine? _egressPolicyEngine;
    private readonly IToolProvenanceVerifier? _provenanceVerifier;
    private readonly ILogger<ScanExecutionEngine> _logger;

    public ScanExecutionEngine(
        IScanToolRegistry toolRegistry,
        IPlatformDbContext dbContext,
        ILogger<ScanExecutionEngine> logger,
        IScannerRuntimeSandbox? runtimeSandbox = null,
        ScanFindingIngestionEngine? ingestionEngine = null,
        IEgressPolicyEngine? egressPolicyEngine = null,
        IToolProvenanceVerifier? provenanceVerifier = null)
    {
        _toolRegistry = toolRegistry ?? throw new ArgumentNullException(nameof(toolRegistry));
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _runtimeSandbox = runtimeSandbox;
        _ingestionEngine = ingestionEngine;
        _egressPolicyEngine = egressPolicyEngine;
        _provenanceVerifier = provenanceVerifier;
    }

    public async Task<PlanExecutionResult> ExecutePlanAsync(
        ResolvedScanPlan plan,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var stopwatch = Stopwatch.StartNew();
        var allIngestedCandidates = new List<FindingCandidate>();
        var invocationDetails = new List<ToolInvocationDetailDto>();

        int toolsCompleted = 0;
        int toolsFailed = 0;

        _logger.LogInformation("Beginning execution of scan plan '{PlanHash}' for Job '{JobId}' ({ToolCount} tools planned).",
            plan.PlanHash, plan.ScanJobId, plan.PlannedInvocations.Count);

        foreach (var plannedInv in plan.PlannedInvocations)
        {
            var invStopwatch = Stopwatch.StartNew();
            var adapter = _toolRegistry.GetAdapter(plannedInv.ToolKey);

            var invocationRecord = new ScanToolInvocationRecord
            {
                Id = Guid.NewGuid(),
                ScanJobId = plan.ScanJobId,
                TenantId = plan.TenantId,
                ToolKey = plannedInv.ToolKey,
                ToolVersion = plannedInv.Version,
                ContainerImageDigest = adapter?.Manifest.ContainerImageDigest ?? "unknown",
                RuleSetVersion = plan.RuleSetVersions.TryGetValue(plannedInv.ToolKey, out var rv) ? rv : plannedInv.Version,
                PlanHash = plan.PlanHash,
                RegistrySnapshotHash = "snapshot_" + plan.PlanHash[..Math.Min(8, plan.PlanHash.Length)],
                ExecutionPhase = plannedInv.Phase.ToString(),
                Status = ToolInvocationStatus.Running.ToString(),
                StartedAtUtc = DateTime.UtcNow
            };

            _dbContext.ScanToolInvocations.Add(invocationRecord);
            await _dbContext.SaveChangesAsync(ct);

            if (adapter == null)
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = $"Scanner adapter '{plannedInv.ToolKey}' is not registered in active registry.";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            // 1. Fail Closed if IScannerRuntimeSandbox is missing
            if (_runtimeSandbox == null)
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = "RUNTIME_SANDBOX_UNAVAILABLE: Active IScannerRuntimeSandbox is required for security execution (Fail-Closed).";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            // 2. Fail Closed if IEgressPolicyEngine is missing
            if (_egressPolicyEngine == null)
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = "EGRESS_POLICY_ENGINE_UNAVAILABLE: Active IEgressPolicyEngine is required for security execution (Fail-Closed).";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            // 3. Fail Closed if IToolProvenanceVerifier is missing
            if (_provenanceVerifier == null)
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = "PROVENANCE_VERIFIER_UNAVAILABLE: Active IToolProvenanceVerifier is required for security execution (Fail-Closed).";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            // 4. Fail Closed if TargetUrl is missing or un-bound
            if (string.IsNullOrWhiteSpace(plan.TargetUrl))
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = "TARGET_BINDING_UNAVAILABLE: No server-authorized target is bound to this scan plan (Fail-Closed).";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            // 5. Version & Planned Snapshot Match Check
            if (plan.RuleSetVersions.TryGetValue(plannedInv.ToolKey, out var expectedVersion) &&
                !string.Equals(expectedVersion, adapter.Manifest.Version, StringComparison.OrdinalIgnoreCase))
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = $"PROVENANCE_SNAPSHOT_MISMATCH: Adapter version '{adapter.Manifest.Version}' does not match planned version '{expectedVersion}'.";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            // 6. Provenance Integrity Check on Adapter Manifest
            if (string.IsNullOrWhiteSpace(adapter.Manifest.ContainerImageDigest) ||
                !adapter.Manifest.ContainerImageDigest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = $"PROVENANCE_INTEGRITY_VIOLATION: Adapter '{plannedInv.ToolKey}' does not have a valid immutable container image digest.";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            var provResult = await _provenanceVerifier.VerifyManifestDigestAsync(adapter.Manifest, ct);
            if (!provResult.IsVerified)
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = $"PROVENANCE_SNAPSHOT_MISMATCH: Adapter container image digest did not verify against supply chain record. Expected: {provResult.ExpectedDigest}, Resolved: {provResult.ResolvedDigest}. Reason: {provResult.ErrorMessage}";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                continue;
            }

            using var toolCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            toolCts.CancelAfter(DefaultPerToolTimeout);

            try
            {
                var execContext = new ScanExecutionContext(
                    ScanJobId: plan.ScanJobId,
                    TargetUrl: plan.TargetUrl,
                    Profile: plan.Profile,
                    TenantId: plan.TenantId,
                    AdditionalOptions: plan.AdditionalOptions
                );

                // 7. Prepare execution in sandbox contract
                var planResult = adapter.PrepareExecution(execContext);

                // 8. Egress Capability & Network Behavior Enforcement
                var networkBehavior = planResult.AdditionalMetadata != null && planResult.AdditionalMetadata.TryGetValue("NetworkBehavior", out var nb) ? nb : null;
                var requiresEgressAuth = planResult.AdditionalMetadata != null && planResult.AdditionalMetadata.TryGetValue("RequiresEgressAuthorization", out var req) && string.Equals(req, "true", StringComparison.OrdinalIgnoreCase);

                // Fail closed if tool attempts CredentialVerification network operations without declaring required egress authorization
                if (string.Equals(networkBehavior, "CredentialVerification", StringComparison.OrdinalIgnoreCase) && !requiresEgressAuth)
                {
                    invStopwatch.Stop();
                    invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                    invocationRecord.ErrorMessage = "EGRESS_AUTHORIZATION_INVALID: Adapter requested CredentialVerification network behavior without declaring required egress authorization.";
                    invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                    invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                    await _dbContext.SaveChangesAsync(ct);

                    toolsFailed++;
                    invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                    continue;
                }

                // 9. Authoritative Target URL & Provider Verification Egress Resolution via IEgressPolicyEngine
                EgressTarget egressTarget;
                try
                {
                    var primaryTarget = await _egressPolicyEngine.EvaluateAndBuildTargetAsync(plan.TargetUrl, ct: toolCts.Token);
                    var combinedApprovedIps = new HashSet<System.Net.IPAddress>(primaryTarget.ApprovedIpAddresses);

                    // If tool requires live verification egress, evaluate and authorize all declared provider destinations
                    if (requiresEgressAuth && planResult.AllowedVerificationDestinations != null && planResult.AllowedVerificationDestinations.Count > 0)
                    {
                        foreach (var providerDest in planResult.AllowedVerificationDestinations)
                        {
                            try
                            {
                                var providerTarget = await _egressPolicyEngine.EvaluateAndBuildTargetAsync(providerDest, ct: toolCts.Token);
                                foreach (var ip in providerTarget.ApprovedIpAddresses)
                                {
                                    combinedApprovedIps.Add(ip);
                                }
                            }
                            catch (Exception pEx)
                            {
                                throw new InvalidOperationException($"PROVIDER_EGRESS_UNAUTHORIZED: Provider verification destination '{providerDest}' is unauthorized or prohibited: {pEx.Message}", pEx);
                            }
                        }
                    }

                    egressTarget = primaryTarget with
                    {
                        ApprovedIpAddresses = combinedApprovedIps
                    };
                }
                catch (Exception ex)
                {
                    invStopwatch.Stop();
                    invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                    invocationRecord.ErrorMessage = ex.Message.StartsWith("PROVIDER_EGRESS_UNAUTHORIZED")
                        ? ex.Message
                        : $"EGRESS_POLICY_VIOLATION: Target '{plan.TargetUrl}' violates egress boundary policy: {ex.Message}";
                    invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                    invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                    await _dbContext.SaveChangesAsync(ct);

                    toolsFailed++;
                    invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));
                    continue;
                }

                var secretLease = new ProviderSecretLease(
                    providerKey: adapter.Manifest.ToolKey,
                    secrets: new Dictionary<string, string>(),
                    duration: TimeSpan.FromMinutes(30)
                );

                var toolArgs = new Dictionary<string, string>();
                for (int i = 0; i < planResult.CommandLineArguments.Count; i++)
                {
                    toolArgs[$"arg_{i}"] = planResult.CommandLineArguments[i];
                }

                // 4. Build Validated Authorized Manifest Map
                var authorizedManifestMap = _toolRegistry.GetAllAdapters()
                    .ToDictionary(a => a.Manifest.ToolKey, a => a.Manifest.ToolKey, StringComparer.OrdinalIgnoreCase);

                var toolRequest = new ToolExecutionRequest(
                    ToolKey: adapter.Manifest.ToolKey,
                    Version: adapter.Manifest.Version,
                    Arguments: toolArgs,
                    ScanJobId: plan.ScanJobId,
                    Timeout: DefaultPerToolTimeout,
                    Executable: adapter.Manifest.ToolKey,
                    ContainerImageRepository: adapter.Manifest.ToolKey,
                    ContainerImageDigest: adapter.Manifest.ContainerImageDigest,
                    AuthorizedManifest: authorizedManifestMap
                );

                // 5. Execute within real IScannerRuntimeSandbox & capture output
                ToolExecutionRawOutput rawOutput;
                var scratchDir = Path.Combine(Path.GetTempPath(), "apihunter-sandbox-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(scratchDir);

                try
                {
                    var sandboxResult = await _runtimeSandbox.ExecuteInSandboxAsync(toolRequest, egressTarget, secretLease, scratchDir, toolCts.Token);
                    var resolvedOutput = ResolveToolOutput(sandboxResult, scratchDir);

                    rawOutput = new ToolExecutionRawOutput(
                        ToolKey: adapter.Manifest.ToolKey,
                        Version: adapter.Manifest.Version,
                        ExitCode: sandboxResult.ExitCode,
                        StandardOutput: resolvedOutput ?? "{}",
                        StandardError: string.Empty,
                        OutputSizeBytes: (long)(resolvedOutput?.Length ?? 0),
                        DurationMs: invStopwatch.ElapsedMilliseconds,
                        ArtifactReference: sandboxResult.ArtifactReference
                    );
                }
                finally
                {
                    try
                    {
                        if (Directory.Exists(scratchDir))
                        {
                            Directory.Delete(scratchDir, true);
                        }
                    }
                    catch
                    {
                        // Suppress temporary scratch directory cleanup error
                    }
                }

                // 3. Parse output through adapter parser
                var parsedResult = await adapter.ParseOutputAsync(execContext, rawOutput, toolCts.Token);

                // 4. Ingest findings into Phase 8 DB if ingestion engine is provided
                if (_ingestionEngine != null && parsedResult.FindingCandidates.Count > 0)
                {
                    var jobContext = new ScanJobContext(
                        JobId: plan.ScanJobId,
                        RepositoryId: plan.TenantId,
                        TargetId: Guid.NewGuid(),
                        TargetUrl: plan.TargetKind.ToString(),
                        ScanProfile: plan.Profile,
                        JobStartedAtUtc: DateTime.UtcNow
                    );

                    await _ingestionEngine.IngestCandidatesAsync(parsedResult.FindingCandidates, jobContext, ct: toolCts.Token);
                }

                allIngestedCandidates.AddRange(parsedResult.FindingCandidates);

                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Completed.ToString();
                invocationRecord.ExitCode = 0;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                invocationRecord.CandidateCount = parsedResult.FindingCandidates.Count;
                invocationRecord.CoverageJson = JsonSerializer.Serialize(parsedResult.Coverage);
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync(ct);

                toolsCompleted++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Completed, parsedResult.Coverage));

                _logger.LogInformation("Tool '{ToolKey}' completed execution in {Elapsed}ms (Emitted {Count} candidates).",
                    adapter.Manifest.ToolKey, invStopwatch.ElapsedMilliseconds, parsedResult.FindingCandidates.Count);
            }
            catch (OperationCanceledException)
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.TimedOut.ToString();
                invocationRecord.ErrorMessage = $"Tool execution exceeded deadline ({DefaultPerToolTimeout.TotalSeconds}s).";
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.TimedOut, null));

                _logger.LogWarning("Tool '{ToolKey}' timed out during execution. Scan continues with remaining tools.",
                    plannedInv.ToolKey);
            }
            catch (Exception ex)
            {
                invStopwatch.Stop();
                invocationRecord.Status = ToolInvocationStatus.Failed.ToString();
                invocationRecord.ErrorMessage = ex.Message;
                invocationRecord.CompletedAtUtc = DateTime.UtcNow;
                invocationRecord.DurationMs = invStopwatch.ElapsedMilliseconds;
                await _dbContext.SaveChangesAsync(ct);

                toolsFailed++;
                invocationDetails.Add(MapToDto(invocationRecord, ToolInvocationStatus.Failed, null));

                _logger.LogWarning(ex, "Tool '{ToolKey}' failed execution. Scan continues with remaining tools.",
                    plannedInv.ToolKey);
            }
        }

        stopwatch.Stop();

        // Determine Overall Execution Status
        OverallScanExecutionStatus overallStatus;
        if (toolsFailed == 0 && toolsCompleted > 0)
        {
            overallStatus = OverallScanExecutionStatus.Completed;
        }
        else if (toolsCompleted > 0 && toolsFailed > 0)
        {
            overallStatus = OverallScanExecutionStatus.CompletedWithToolFailures;
        }
        else if (toolsCompleted == 0 && toolsFailed > 0)
        {
            overallStatus = OverallScanExecutionStatus.Failed;
        }
        else
        {
            overallStatus = OverallScanExecutionStatus.Completed;
        }

        _logger.LogInformation("Finished scan execution for Job '{JobId}'. Overall Status: {Status} (Completed: {Completed}, Failed: {Failed}, Total Findings: {Findings}) in {Duration}ms.",
            plan.ScanJobId, overallStatus, toolsCompleted, toolsFailed, allIngestedCandidates.Count, stopwatch.ElapsedMilliseconds);

        return new PlanExecutionResult(
            ScanJobId: plan.ScanJobId,
            OverallStatus: overallStatus,
            TotalFindingsIngested: allIngestedCandidates.Count,
            IngestedCandidates: allIngestedCandidates.AsReadOnly(),
            Invocations: invocationDetails.AsReadOnly(),
            TotalDurationMs: stopwatch.ElapsedMilliseconds
        );
    }

    public async Task<ScanJobExecutionSummaryDto?> GetExecutionSummaryAsync(
        Guid scanJobId,
        Guid tenantId,
        CancellationToken ct = default)
    {
        var records = await _dbContext.ScanToolInvocations
            .AsNoTracking()
            .Where(i => i.ScanJobId == scanJobId && i.TenantId == tenantId)
            .OrderBy(i => i.StartedAtUtc)
            .ToListAsync(ct);

        if (records.Count == 0) return null;

        var invocations = records.Select(r =>
        {
            Enum.TryParse<ToolInvocationStatus>(r.Status, true, out var parsedStatus);
            ScannerCoverage? coverage = null;
            if (!string.IsNullOrWhiteSpace(r.CoverageJson) && r.CoverageJson != "{}")
            {
                try { coverage = JsonSerializer.Deserialize<ScannerCoverage>(r.CoverageJson); } catch { }
            }

            return MapToDto(r, parsedStatus, coverage);
        }).ToList();

        var completedCount = invocations.Count(i => i.Status == ToolInvocationStatus.Completed);
        var failedCount = invocations.Count(i => i.Status is ToolInvocationStatus.Failed or ToolInvocationStatus.TimedOut);
        var totalDuration = invocations.Sum(i => i.DurationMs);
        var totalFindings = invocations.Sum(i => i.CandidateCount);

        var first = records[0];
        OverallScanExecutionStatus overall;
        if (failedCount == 0) overall = OverallScanExecutionStatus.Completed;
        else if (completedCount > 0) overall = OverallScanExecutionStatus.CompletedWithToolFailures;
        else overall = OverallScanExecutionStatus.Failed;

        return new ScanJobExecutionSummaryDto(
            ScanJobId: scanJobId,
            TenantId: tenantId,
            PlanHash: first.PlanHash,
            RegistrySnapshotHash: first.RegistrySnapshotHash,
            OverallStatus: overall,
            TotalToolsPlanned: records.Count,
            ToolsCompleted: completedCount,
            ToolsFailed: failedCount,
            TotalFindingsIngested: totalFindings,
            TotalExecutionDurationMs: totalDuration,
            Invocations: invocations.AsReadOnly()
        );
    }

    private static ToolInvocationDetailDto MapToDto(
        ScanToolInvocationRecord record,
        ToolInvocationStatus status,
        ScannerCoverage? coverage)
    {
        return new ToolInvocationDetailDto(
            InvocationId: record.Id,
            ToolKey: record.ToolKey,
            ToolVersion: record.ToolVersion,
            ContainerImageDigest: record.ContainerImageDigest,
            RuleSetVersion: record.RuleSetVersion,
            ExecutionPhase: record.ExecutionPhase,
            Status: status,
            ExitCode: record.ExitCode,
            DurationMs: record.DurationMs,
            CandidateCount: record.CandidateCount,
            Coverage: coverage,
            ErrorMessage: record.ErrorMessage,
            StartedAtUtc: record.StartedAtUtc,
            CompletedAtUtc: record.CompletedAtUtc
        );
    }

    private static string? ResolveToolOutput(ToolExecutionResult result, string scratchDirectory)
    {
        if (!string.IsNullOrWhiteSpace(result.ArtifactReference))
        {
            if (System.IO.File.Exists(result.ArtifactReference))
            {
                try { return System.IO.File.ReadAllText(result.ArtifactReference); } catch { }
            }

            if (result.ArtifactReference.TrimStart().StartsWith("{") || result.ArtifactReference.TrimStart().StartsWith("["))
            {
                return result.ArtifactReference;
            }
        }

        var defaultArtifactFile = System.IO.Path.Combine(scratchDirectory, $"{result.ToolKey}_output.json");
        if (System.IO.File.Exists(defaultArtifactFile))
        {
            try { return System.IO.File.ReadAllText(defaultArtifactFile); } catch { }
        }

        return null;
    }
}
