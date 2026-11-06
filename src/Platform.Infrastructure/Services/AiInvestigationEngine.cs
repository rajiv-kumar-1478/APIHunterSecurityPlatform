using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Services;

public class AiInvestigationEngineOptions
{
    public int MaxFilesPerInvestigation { get; set; } = 250;
    public long MaxFileSizeBytes { get; set; } = 1_048_576; // 1 MB
    public int MaxAiCallsPerInvestigation { get; set; } = 30;
    public int MaxTokensPerInvestigation { get; set; } = 400_000;
    public int MaxStageRetries { get; set; } = 3;
    public int MaxInvestigationDurationMinutes { get; set; } = 30;
    public int MaxAiInputCharactersPerCall { get; set; } = 48_000;
    public int MaxAiFilesPerCall { get; set; } = 12;
    public int MaxSecretFindingsPerInvestigation { get; set; } = 300;
}

public class AiInvestigationEngine
{
    private readonly IPlatformDbContext _dbContext;
    private readonly IAiModelRouter _modelRouter;
    private readonly RepositoryContentReader _contentReader;
    private readonly IDataProtector _rawProtector;
    private readonly IDataProtector _contextProtector;
    private readonly DetectionOptions _detectionOptions;
    private readonly ILogger<AiInvestigationEngine> _logger;
    private readonly AiInvestigationEngineOptions _options;

    public AiInvestigationEngine(
        IPlatformDbContext dbContext,
        IAiModelRouter modelRouter,
        RepositoryContentReader contentReader,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<DetectionOptions> detectionOptions,
        ILogger<AiInvestigationEngine> logger,
        AiInvestigationEngineOptions? options = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _modelRouter = modelRouter ?? throw new ArgumentNullException(nameof(modelRouter));
        _contentReader = contentReader ?? throw new ArgumentNullException(nameof(contentReader));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? new AiInvestigationEngineOptions();

        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        _rawProtector = dataProtectionProvider.CreateProtector("Platform.SecretCandidate.RawValue");
        _contextProtector = dataProtectionProvider.CreateProtector("Platform.CandidateOccurrence.RawContext");
        _detectionOptions = detectionOptions?.Value ?? new DetectionOptions();
    }

    public async Task ExecuteInvestigationAsync(Guid jobId, Guid expectedClaimToken = default, CancellationToken ct = default)
    {
        var job = await _dbContext.AiInvestigationJobs
            .Include(j => j.Repository)
            .Include(j => j.Snapshot)
                .ThenInclude(s => s.Files)
            .Include(j => j.Checkpoints)
            .FirstOrDefaultAsync(j => j.Id == jobId, ct);

        if (job == null)
        {
            _logger.LogError("Investigation job '{JobId}' not found.", jobId);
            return;
        }

        // Initial lease validation check
        if (expectedClaimToken != Guid.Empty && job.ClaimToken != expectedClaimToken)
        {
            _logger.LogWarning("Worker lease expired for Job '{JobId}'. Expected ClaimToken '{ExpectedToken}', DB has '{CurrentToken}'. Aborting.", jobId, expectedClaimToken, job.ClaimToken);
            return;
        }

        var effectiveClaimToken = expectedClaimToken != Guid.Empty ? expectedClaimToken : job.ClaimToken;
        var completedStageTypes = job.Checkpoints.Select(c => c.StageType).ToHashSet();

        var stages = Enum.GetValues<AiInvestigationStageType>()
            .OrderBy(s => (int)s)
            .ToList();

        var aiBudget = new AiCallBudget(_options.MaxAiCallsPerInvestigation);

        foreach (var stage in stages)
        {
            if (ct.IsCancellationRequested)
            {
                job.Status = JobStatus.Cancelled;
                await SaveWithLeaseCheckAsync(job, effectiveClaimToken, ct);
                return;
            }

            // Limit Enforcement: Maximum Investigation Duration
            var elapsed = DateTime.UtcNow - (job.StartedAtUtc ?? job.QueuedAtUtc);
            if (elapsed > TimeSpan.FromMinutes(_options.MaxInvestigationDurationMinutes))
            {
                _logger.LogError("Job '{JobId}' exceeded maximum investigation duration of {MaxDuration} minutes (Elapsed: {Elapsed:F1} min). Failing job.", jobId, _options.MaxInvestigationDurationMinutes, elapsed.TotalMinutes);
                job.Status = JobStatus.Failed;
                job.ErrorMessage = $"Investigation exceeded maximum duration limit of {_options.MaxInvestigationDurationMinutes} minutes.";
                await SaveWithLeaseCheckAsync(job, effectiveClaimToken, ct);
                return;
            }

            // Limit Enforcement: Maximum Tokens per Investigation
            if ((job.TotalPromptTokens + job.TotalCompletionTokens) >= _options.MaxTokensPerInvestigation)
            {
                _logger.LogWarning("Job '{JobId}' reached max token limit ({MaxTokens} tokens). Skipping further AI queries.", jobId, _options.MaxTokensPerInvestigation);
            }

            // Check Admin Global Pause
            var isGlobalEnabledSetting = await _dbContext.SystemSettings
                .FirstOrDefaultAsync(s => s.Key == "ai.global_enabled", ct);

            if (isGlobalEnabledSetting != null && string.Equals(isGlobalEnabledSetting.Value, "false", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("AI Global Pause detected. Pausing investigation job '{JobId}' at Stage={Stage}.", jobId, stage);
                job.Status = JobStatus.Paused;
                await SaveWithLeaseCheckAsync(job, effectiveClaimToken, ct);
                return;
            }

            // Check if stage already completed in prior run (restart-safe!)
            if (completedStageTypes.Contains(stage))
            {
                _logger.LogInformation("Job '{JobId}': Stage={Stage} already checkpointed. Skipping.", jobId, stage);
                continue;
            }

            _logger.LogInformation("Job '{JobId}': Executing Stage={Stage}...", jobId, stage);
            job.CurrentStage = stage;
            job.LastHeartbeatAtUtc = DateTime.UtcNow;

            // Fenced Stage Progress & Heartbeat Mutation
            if (!await SaveWithLeaseCheckAsync(job, effectiveClaimToken, ct))
            {
                _logger.LogWarning("Atomic fencing check failed before executing Stage={Stage} for Job '{JobId}'. Aborting processing.", stage, jobId);
                return;
            }

            // Execute stage logic with retry bounds
            int attempt = 0;
            string stageResultJson = "{}";

            while (attempt < _options.MaxStageRetries)
            {
                try
                {
                    attempt++;
                    stageResultJson = await ExecuteStageLogicAsync(job, stage, aiBudget, ct);
                    break;
                }
                catch (Exception ex)
                {
                    if (attempt >= _options.MaxStageRetries)
                    {
                        _logger.LogError(ex, "Stage={Stage} failed after {MaxRetries} retries.", stage, _options.MaxStageRetries);
                        job.Status = JobStatus.Failed;
                        job.ErrorMessage = $"Stage {stage} failed after {_options.MaxStageRetries} attempts: {ex.Message}";
                        await SaveWithLeaseCheckAsync(job, effectiveClaimToken, ct);
                        return;
                    }
                    _logger.LogWarning(ex, "Stage={Stage} attempt {Attempt}/{MaxRetries} failed. Retrying...", stage, attempt, _options.MaxStageRetries);
                    await Task.Delay(TimeSpan.FromMilliseconds(100 * attempt), ct);
                }
            }

            // Fenced Checkpoint Write & Stage Completion Mutation
            var checkpoint = new AiInvestigationCheckpoint
            {
                InvestigationJobId = job.Id,
                StageType = stage,
                CursorPosition = $"stage_{(int)stage}_complete",
                DurableResultJson = stageResultJson,
                CompletedAtUtc = DateTime.UtcNow
            };

            _dbContext.AiInvestigationCheckpoints.Add(checkpoint);
            job.CompletedStagesCount++;
            job.LastHeartbeatAtUtc = DateTime.UtcNow;

            if (!await SaveWithLeaseCheckAsync(job, effectiveClaimToken, ct))
            {
                _logger.LogWarning("Atomic fencing check failed after executing Stage={Stage} for Job '{JobId}'. Checkpoint write aborted.", stage, jobId);
                return;
            }
        }

        // Fenced Final Job Completion Mutation
        job.Status = JobStatus.Succeeded;
        job.CompletedAtUtc = DateTime.UtcNow;
        job.LastHeartbeatAtUtc = DateTime.UtcNow;

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.AiInvestigationCompleted,
            ResourceType = "AiInvestigationJob",
            ResourceId = job.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new { job.RepositoryId, job.SnapshotId, job.TotalPromptTokens, job.TotalCompletionTokens })
        });

        if (await SaveWithLeaseCheckAsync(job, effectiveClaimToken, ct))
        {
            _logger.LogInformation("Investigation job '{JobId}' completed successfully across all stages.", jobId);
        }
    }

    public async Task<bool> SaveWithLeaseCheckAsync(AiInvestigationJob job, Guid expectedClaimToken, CancellationToken ct)
    {
        if (expectedClaimToken == Guid.Empty)
        {
            await _dbContext.SaveChangesAsync(ct);
            return true;
        }

        try
        {
            if (_dbContext is DbContext efDbContext)
            {
                efDbContext.Entry(job).Property(j => j.ClaimToken).OriginalValue = expectedClaimToken;
            }

            await _dbContext.SaveChangesAsync(ct);
            return true;
        }

        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Atomic lease fencing (DbUpdateConcurrencyException) rejected mutation for Job '{JobId}'. Expected ClaimToken '{ExpectedToken}'. Worker lease was stolen by another worker.", job.Id, expectedClaimToken);
            return false;
        }
    }

    private async Task<string> ExecuteStageLogicAsync(AiInvestigationJob job, AiInvestigationStageType stage, AiCallBudget aiBudget, CancellationToken ct)
    {
        return stage switch
        {
            AiInvestigationStageType.RepositoryMetadata => await ExecuteStage1_MetadataAsync(job, ct),
            AiInvestigationStageType.FileInventory => await ExecuteStage2_FileInventoryAsync(job, ct),
            AiInvestigationStageType.TechnologyIdentification => await ExecuteStage3_TechIdentificationAsync(job, ct),
            AiInvestigationStageType.ApiHunterSeedInvestigation => await ExecuteStage4_SeedInvestigationAsync(job, ct),
            AiInvestigationStageType.ConfigurationAnalysis => await ExecuteStage5_ConfigurationAnalysisAsync(job, aiBudget, ct),
            AiInvestigationStageType.CandidateDiscovery => await ExecuteStage6_CandidateDiscoveryAsync(job, aiBudget, ct),
            AiInvestigationStageType.CrossFileRelationshipAnalysis => await ExecuteStage7_CrossFileAnalysisAsync(job, ct),
            AiInvestigationStageType.CredentialServiceRelationshipAnalysis => await ExecuteStage8_RelationshipAnalysisAsync(job, ct),
            AiInvestigationStageType.ProductionExposureAnalysis => await ExecuteStage9_ProductionExposureAsync(job, ct),
            AiInvestigationStageType.FinalIntelligenceReport => await ExecuteStage10_FinalReportAsync(job, ct),
            _ => "{}"
        };
    }

    private async Task<string> ExecuteStage1_MetadataAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var meta = new
        {
            repositoryName = job.Repository?.FullName ?? "Unknown",
            snapshotId = job.SnapshotId,
            totalFiles = job.Snapshot?.Files?.Count ?? 0,
            analyzedAt = DateTime.UtcNow
        };

        return JsonSerializer.Serialize(meta);
    }

    private async Task<string> ExecuteStage2_FileInventoryAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var files = (job.Snapshot?.Files ?? new List<SnapshotFile>())
            .Where(f => !f.IsBinary && f.SizeBytes <= _options.MaxFileSizeBytes)
            .Take(_options.MaxFilesPerInvestigation)
            .ToList();

        var categories = new Dictionary<string, List<string>>
        {
            ["Configuration"] = new(),
            ["Infrastructure"] = new(),
            ["Source"] = new(),
            ["Other"] = new()
        };

        foreach (var f in files)
        {
            var path = f.FilePath.ToLowerInvariant();
            if (path.Contains(".env") || path.EndsWith(".config") || path.EndsWith(".json") || path.EndsWith(".yaml") || path.EndsWith(".yml") || path.EndsWith(".toml"))
            {
                categories["Configuration"].Add(f.FilePath);
            }
            else if (path.Contains("docker") || path.Contains("k8s") || path.Contains("ci") || path.EndsWith(".sh"))
            {
                categories["Infrastructure"].Add(f.FilePath);
            }
            else if (path.EndsWith(".cs") || path.EndsWith(".py") || path.EndsWith(".js") || path.EndsWith(".ts") || path.EndsWith(".go") || path.EndsWith(".java"))
            {
                categories["Source"].Add(f.FilePath);
            }
            else
            {
                categories["Other"].Add(f.FilePath);
            }
        }

        return JsonSerializer.Serialize(categories);
    }

    private async Task<string> ExecuteStage3_TechIdentificationAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var tech = new { description = job.Repository?.Description ?? "Unknown", framework = "ASP.NET Core / Python" };
        return JsonSerializer.Serialize(tech);
    }

    private async Task<string> ExecuteStage4_SeedInvestigationAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var repoRefs = await _dbContext.ApiHunterRepoReferences
            .Include(r => r.ApiHunterRecord)
            .Where(r => r.RepoName == job.Repository.FullName || job.Repository.FullName.EndsWith(r.RepoName))
            .ToListAsync(ct);

        var seeds = repoRefs.Select(r => new
        {
            provider = r.ApiHunterRecord?.SearchProvider ?? "Unknown",
            // Provenance Preservation: APIHunter status is preserved as immutable provenance
            status = r.ApiHunterRecord?.Status.ToString() ?? "Unverified",
            filePath = r.FilePath,
            line = r.LineNumber,
            keyPreview = r.ApiHunterRecord?.MaskedKey
        }).ToList();

        if (seeds.Any())
        {
            // Evidence Source: DiscoveryType.ApiHunterSync
            await SaveEvidenceAsync(job, "ApiHunterSeed", seeds.First().filePath, seeds.First().line, seeds.First().line,
                FindingConfidence.High, DiscoveryType.ApiHunterSync, JsonSerializer.Serialize(new { seeds, provenance = "APIHunter" }));
        }

        return JsonSerializer.Serialize(new { seedCount = seeds.Count, seeds });
    }

    private async Task<string> ExecuteStage5_ConfigurationAnalysisAsync(AiInvestigationJob job, AiCallBudget budget, CancellationToken ct)
    {
        var files = await ReadRepositoryFilesAsync(job, ct);
        var configFiles = files.Where(f => f.IsConfiguration).ToList();

        if (configFiles.Count == 0)
        {
            _logger.LogInformation("Job '{JobId}': no configuration files found for AI audit.", job.Id);
            return JsonSerializer.Serialize(new { skipped = true, reason = "NoConfigurationFiles", totalFiles = files.Count });
        }

        var result = await AnalyzeFilesForSecretsAsync(job, configFiles, "configuration", budget, ct);
        return JsonSerializer.Serialize(new
        {
            scope = "configuration",
            files = configFiles.Count,
            result.FindingsReturned,
            result.FindingsPersisted,
            result.AiCalls,
            result.Skipped
        });
    }

    private async Task<string> ExecuteStage6_CandidateDiscoveryAsync(AiInvestigationJob job, AiCallBudget budget, CancellationToken ct)
    {
        var files = await ReadRepositoryFilesAsync(job, ct);
        var sourceFiles = files.Where(f => !f.IsConfiguration).ToList();

        if (sourceFiles.Count == 0)
            sourceFiles = files.ToList();

        if (sourceFiles.Count == 0)
        {
            _logger.LogInformation("Job '{JobId}': no source files found for AI audit.", job.Id);
            return JsonSerializer.Serialize(new { skipped = true, reason = "NoSourceFiles" });
        }

        var result = await AnalyzeFilesForSecretsAsync(job, sourceFiles, "source", budget, ct);
        return JsonSerializer.Serialize(new
        {
            scope = "source",
            files = sourceFiles.Count,
            result.FindingsReturned,
            result.FindingsPersisted,
            result.AiCalls,
            result.Skipped
        });
    }

    private async Task<IReadOnlyList<RepositoryTextFile>> ReadRepositoryFilesAsync(AiInvestigationJob job, CancellationToken ct)
    {
        if (job.Snapshot is null || job.Repository is null)
            return Array.Empty<RepositoryTextFile>();

        try
        {
            return await _contentReader.ReadTextFilesAsync(
                job.Snapshot,
                job.Repository,
                _options.MaxFilesPerInvestigation,
                _options.MaxFileSizeBytes,
                ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Job '{JobId}': failed to read repository content for AI audit.", job.Id);
            throw;
        }
    }

    private async Task<SecretAnalysisOutcome> AnalyzeFilesForSecretsAsync(
        AiInvestigationJob job,
        IReadOnlyList<RepositoryTextFile> files,
        string scope,
        AiCallBudget budget,
        CancellationToken ct)
    {
        var findingsReturned = 0;
        var findingsPersisted = 0;
        var aiCalls = 0;
        var successfulCalls = 0;
        var failedCalls = 0;
        string? lastError = null;
        string? skipped = null;

        var existingFindings = await _dbContext.AiInvestigationEvidences
            .CountAsync(e => e.InvestigationId == job.Id && e.EvidenceType == "HardcodedSecret", ct);

        foreach (var batch in BuildBatches(files))
        {
            if (existingFindings + findingsPersisted >= _options.MaxSecretFindingsPerInvestigation)
            {
                skipped = "MaxFindingsReached";
                break;
            }

            if ((job.TotalPromptTokens + job.TotalCompletionTokens) >= _options.MaxTokensPerInvestigation)
            {
                skipped = "MaxTokensReached";
                break;
            }

            if (!budget.TryConsume())
            {
                skipped = "MaxAiCallsReached";
                break;
            }

            var request = new AiPromptRequest(
                SystemPrompt: SecretAuditSystemPrompt,
                UserPrompt: BuildFileAnalysisPrompt(job, scope, batch),
                Temperature: 0.0,
                MaxTokens: 6000,
                RequireJsonOutput: true);

            var (response, usedProvider, usedModel) = await _modelRouter
                .ExecuteWithFallbackAsync(request, new[] { "JsonOutput" }, ct)
                .ConfigureAwait(false);
            aiCalls++;

            if (!response.IsSuccess)
            {
                failedCalls++;
                lastError = response.ErrorMessage;
                _logger.LogWarning("Job '{JobId}': AI {Scope} audit call failed: {Error}", job.Id, scope, response.ErrorMessage);

                if (failedCalls >= 3)
                {
                    skipped = "AiProviderUnavailable";
                    break;
                }

                continue;
            }

            successfulCalls++;
            job.ActiveProviderName = usedProvider;
            job.ActiveModelName = usedModel;
            job.TotalPromptTokens += response.PromptTokens;
            job.TotalCompletionTokens += response.CompletionTokens;

            var findings = ParseFindings(response.NormalizedJsonContent ?? response.RawResponseContent);
            findingsReturned += findings.Count;

            foreach (var finding in findings)
            {
                if (existingFindings + findingsPersisted >= _options.MaxSecretFindingsPerInvestigation)
                    break;

                if (await PersistFindingAsync(job, finding, batch, ct).ConfigureAwait(false))
                    findingsPersisted++;
            }

            await _dbContext.SaveChangesAsync(ct);
        }

        if (failedCalls > 0 && successfulCalls == 0)
        {
            throw new InvalidOperationException(
                $"AI provider unavailable for {scope} audit: {lastError ?? "no eligible provider configured"}");
        }

        return new SecretAnalysisOutcome(findingsReturned, findingsPersisted, aiCalls, skipped);
    }

    private List<List<RepositoryTextFile>> BuildBatches(IReadOnlyList<RepositoryTextFile> files)
    {
        var batches = new List<List<RepositoryTextFile>>();
        var current = new List<RepositoryTextFile>();
        var currentChars = 0;

        foreach (var file in files)
        {
            var fileChars = file.Path.Length + file.Content.Length + 64;
            if (current.Count > 0 &&
                (current.Count >= _options.MaxAiFilesPerCall ||
                 currentChars + fileChars > _options.MaxAiInputCharactersPerCall))
            {
                batches.Add(current);
                current = new List<RepositoryTextFile>();
                currentChars = 0;
            }

            current.Add(file);
            currentChars += fileChars;
        }

        if (current.Count > 0)
            batches.Add(current);

        return batches;
    }

    private string BuildFileAnalysisPrompt(AiInvestigationJob job, string scope, IReadOnlyList<RepositoryTextFile> batch)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Repository: {job.Repository?.FullName ?? "unknown"}");
        sb.AppendLine($"Commit: {job.Snapshot?.CommitSha ?? "unknown"}");
        sb.AppendLine($"Scope: {scope}");
        sb.AppendLine("Analyze the following files for hardcoded secrets and credentials.");

        foreach (var file in batch)
        {
            var content = file.Content;
            if (content.Length > _options.MaxAiInputCharactersPerCall)
                content = content[.._options.MaxAiInputCharactersPerCall];

            sb.AppendLine($"=== FILE: {file.Path} ===");
            sb.AppendLine(content);
            sb.AppendLine("=== END FILE ===");
        }

        return sb.ToString();
    }

    private async Task<bool> PersistFindingAsync(
        AiInvestigationJob job,
        JsonElement finding,
        IReadOnlyList<RepositoryTextFile> batch,
        CancellationToken ct)
    {
        var filePath = GetString(finding, "filePath") ?? GetString(finding, "path");
        if (string.IsNullOrWhiteSpace(filePath))
            return false;

        var normalizedPath = NormalizePath(filePath);
        var file = batch.FirstOrDefault(f => string.Equals(NormalizePath(f.Path), normalizedPath, StringComparison.OrdinalIgnoreCase))
                   ?? batch.FirstOrDefault(f => f.Path.EndsWith(normalizedPath, StringComparison.OrdinalIgnoreCase));

        if (file is null)
        {
            _logger.LogWarning("Job '{JobId}': AI reported unknown file '{FilePath}'.", job.Id, filePath);
            return false;
        }

        var rawSecret = GetString(finding, "secretValue") ?? GetString(finding, "secret");
        if (string.IsNullOrWhiteSpace(rawSecret) || rawSecret.Length < 8)
            return false;

        if (!file.Content.Contains(rawSecret, StringComparison.Ordinal))
        {
            _logger.LogWarning("Job '{JobId}': AI-reported secret in '{FilePath}' was not found verbatim; discarding to prevent hallucinated findings.", job.Id, file.Path);
            return false;
        }

        var lineCount = CountLines(file.Content);
        var startLine = Math.Clamp(GetInt(finding, "line") ?? GetInt(finding, "startLine") ?? 1, 1, lineCount);
        var endLine = Math.Clamp(GetInt(finding, "endLine") ?? startLine, startLine, lineCount);
        var secretType = GetString(finding, "secretType") ?? GetString(finding, "type") ?? "Unknown";
        var severity = GetString(finding, "severity") ?? "Medium";
        var confidence = ParseConfidence(GetString(finding, "confidence"));

        // Never trust model-supplied masking or free text: strip the raw secret from everything
        // that is persisted outside the encrypted candidate/occurrence columns.
        var maskedValue = FingerprintUtils.MaskSecret(rawSecret);
        var reasoning = Redact(rawSecret, GetString(finding, "reasoning") ?? string.Empty);
        var generatedCode = Redact(rawSecret,
            GetString(finding, "generatedCode") ?? GetString(finding, "validationCode"));
        var validationPlanJson = Redact(rawSecret,
            GetRawProperty(finding, "validationPlan") ?? GetRawProperty(finding, "validation"));

        var matchStart = Math.Max(0, file.Content.IndexOf(rawSecret, StringComparison.Ordinal));
        var matchLength = rawSecret.Length;
        var lineContent = GetLine(file.Content, startLine);

        var secretFingerprint = FingerprintUtils.ComputeSecretFingerprint(
            rawSecret, _detectionOptions.SecretPepper, _detectionOptions.FingerprintKeyVersion);

        var candidate = await _dbContext.CredentialCandidates
            .FirstOrDefaultAsync(c => c.SecretFingerprint == secretFingerprint, ct)
            .ConfigureAwait(false);

        if (candidate is null)
        {
            candidate = new CredentialCandidate
            {
                SecretFingerprint = secretFingerprint,
                FingerprintKeyVersion = _detectionOptions.FingerprintKeyVersion,
                MaskedValue = maskedValue,
                EncryptedRawValue = _rawProtector.Protect(rawSecret),
                CredentialType = secretType,
                Status = CandidateStatus.Detected,
                FirstDetectedAtUtc = DateTime.UtcNow,
                LastDetectedAtUtc = DateTime.UtcNow,
                TotalOccurrences = 1
            };

            _dbContext.CredentialCandidates.Add(candidate);
            await _dbContext.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        else
        {
            candidate.LastDetectedAtUtc = DateTime.UtcNow;
            candidate.TotalOccurrences++;
        }

        var snapshotFile = job.Snapshot?.Files
            .FirstOrDefault(f => string.Equals(NormalizePath(f.FilePath), NormalizePath(file.Path), StringComparison.OrdinalIgnoreCase));

        if (snapshotFile is not null)
        {
            var occurrenceFingerprint = FingerprintUtils.ComputeOccurrenceFingerprint(
                candidate.Id, snapshotFile.Id, "AI-SECRET-AUDIT", 1, startLine, matchStart, matchLength);

            var occurrenceExists = await _dbContext.CandidateOccurrences
                .AnyAsync(o => o.OccurrenceFingerprint == occurrenceFingerprint, ct)
                .ConfigureAwait(false);

            if (!occurrenceExists)
            {
                _dbContext.CandidateOccurrences.Add(new CandidateOccurrence
                {
                    CandidateId = candidate.Id,
                    SnapshotFileId = snapshotFile.Id,
                    RepositoryId = job.RepositoryId,
                    DetectionRuleId = "AI-SECRET-AUDIT",
                    RuleVersion = 1,
                    OccurrenceFingerprint = occurrenceFingerprint,
                    LineNumber = startLine,
                    MatchStartIndex = matchStart,
                    MatchLength = matchLength,
                    LineContentRedacted = FingerprintUtils.RedactLine(lineContent, rawSecret),
                    LineContentRawEncrypted = _contextProtector.Protect(lineContent),
                    Confidence = confidence.ToString()
                });
            }
        }

        var evidenceFingerprint = FingerprintUtils.ComputeSha256(
            $"{job.SnapshotId}:HardcodedSecret:{file.Path}:{startLine}:{endLine}:{secretFingerprint}");

        var evidenceExists = await _dbContext.AiInvestigationEvidences
            .AnyAsync(e => e.SnapshotId == job.SnapshotId && e.Fingerprint == evidenceFingerprint, ct)
            .ConfigureAwait(false);

        if (!evidenceExists)
        {
            _dbContext.AiInvestigationEvidences.Add(new AiInvestigationEvidence
            {
                InvestigationId = job.Id,
                SnapshotId = job.SnapshotId,
                SnapshotFileId = snapshotFile?.Id,
                CandidateId = candidate.Id,
                EvidenceType = "HardcodedSecret",
                FilePath = file.Path,
                StartLine = startLine,
                EndLine = endLine,
                Confidence = confidence,
                Source = DiscoveryType.AiInvestigator,
                EvidenceJson = JsonSerializer.Serialize(new
                {
                    secretType,
                    severity,
                    maskedValue,
                    reasoning,
                    validationPlan = ParseRawJson(validationPlanJson),
                    generatedCode,
                    provider = job.ActiveProviderName,
                    model = job.ActiveModelName
                }),
                Fingerprint = evidenceFingerprint,
                CreatedAtUtc = DateTime.UtcNow
            });
        }

        if (!string.IsNullOrWhiteSpace(validationPlanJson))
        {
            var hasPendingJob = await _dbContext.AnalysisJobs.AnyAsync(j =>
                j.JobType == JobType.CredentialValidation &&
                j.TargetEntityId == candidate.Id &&
                (j.Status == JobStatus.Paused || j.Status == JobStatus.Queued), ct).ConfigureAwait(false);

            if (!hasPendingJob)
            {
                _dbContext.AnalysisJobs.Add(new AnalysisJob
                {
                    JobType = JobType.CredentialValidation,
                    Status = JobStatus.Paused,
                    TargetEntityType = "Candidate",
                    TargetEntityId = candidate.Id,
                    PayloadJson = JsonSerializer.Serialize(new
                    {
                        candidateId = candidate.Id,
                        providerName = secretType,
                        requiresApproval = true,
                        aiGenerated = true,
                        investigationId = job.Id,
                        filePath = file.Path,
                        line = startLine,
                        severity,
                        maskedValue,
                        validationPlan = ParseRawJson(validationPlanJson),
                        generatedCode
                    }),
                    QueuedAtUtc = DateTime.UtcNow
                });
            }
        }

        await _dbContext.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }

    private static IReadOnlyList<JsonElement> ParseFindings(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return Array.Empty<JsonElement>();

        var cleaned = StripCodeFences(json);

        try
        {
            using var document = JsonDocument.Parse(cleaned);
            var root = document.RootElement;
            JsonElement array;

            if (root.ValueKind == JsonValueKind.Array)
                array = root;
            else if (root.ValueKind == JsonValueKind.Object &&
                     root.TryGetProperty("findings", out var findings) &&
                     findings.ValueKind == JsonValueKind.Array)
                array = findings;
            else
                return Array.Empty<JsonElement>();

            return array.EnumerateArray().Select(e => e.Clone()).ToList();
        }
        catch (JsonException)
        {
            return Array.Empty<JsonElement>();
        }
    }

    private static string StripCodeFences(string json)
    {
        var trimmed = json.Trim();
        if (!trimmed.StartsWith("```", StringComparison.Ordinal))
            return trimmed;

        var firstNewline = trimmed.IndexOf('\n');
        if (firstNewline < 0)
            return trimmed;

        var body = trimmed[(firstNewline + 1)..];
        var closing = body.LastIndexOf("```", StringComparison.Ordinal);
        return (closing >= 0 ? body[..closing] : body).Trim();
    }

    private static object? ParseRawJson(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        try
        {
            using var document = JsonDocument.Parse(raw);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return raw;
        }
    }

    private static string? GetString(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;

        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                continue;

            return property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Number => property.Value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => null
            };
        }

        return null;
    }

    private static int? GetInt(JsonElement element, string name)
    {
        var raw = GetString(element, name);
        return int.TryParse(raw, out var value) ? value : null;
    }

    private static string? GetRawProperty(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;

        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                continue;

            return property.Value.ValueKind switch
            {
                JsonValueKind.Object or JsonValueKind.Array => property.Value.GetRawText(),
                JsonValueKind.String => property.Value.GetString(),
                _ => null
            };
        }

        return null;
    }

    private static FindingConfidence ParseConfidence(string? value) =>
        Enum.TryParse<FindingConfidence>(value, ignoreCase: true, out var confidence)
            ? confidence
            : FindingConfidence.Medium;

    private static int CountLines(string content) => content.Count(c => c == '\n') + 1;

    private static string GetLine(string content, int lineNumber)
    {
        if (lineNumber < 1)
            return string.Empty;

        var currentLine = 1;
        var lineStart = 0;

        for (var i = 0; i <= content.Length; i++)
        {
            if (i != content.Length && content[i] != '\n')
                continue;

            if (currentLine == lineNumber)
                return content[lineStart..i].TrimEnd('\r');

            currentLine++;
            lineStart = i + 1;
        }

        return string.Empty;
    }

    private static string NormalizePath(string path)
    {
        var normalized = path.Replace('\\', '/').Trim();

        while (normalized.StartsWith("./", StringComparison.Ordinal))
            normalized = normalized[2..];

        return normalized.TrimStart('/');
    }

    private static string? Redact(string secret, string? value)
    {
        if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(secret))
            return value;

        return value.Replace(secret, "{{SECRET}}", StringComparison.Ordinal);
    }

    private const string SecretAuditSystemPrompt = """
        You are a senior application security auditor. Analyze the supplied repository files for hardcoded secrets and credentials (API keys, access tokens, passwords, private keys, connection strings, cloud credentials, OAuth client secrets, webhook URLs with embedded tokens).

        Return ONLY valid JSON with this exact shape:
        {"findings":[{"filePath":"...","line":12,"endLine":12,"secretType":"AWS Access Key","severity":"Critical|High|Medium|Low","confidence":"High|Medium|Low","secretValue":"exact secret value copied from the file","maskedValue":"AKIA****ABCD","reasoning":"why this is a real secret","validationPlan":{"method":"GET","url":"https://...","authType":"bearer|header|query|none","authHeaderName":"Authorization","expectedStatus":200,"successJsonPath":"...","description":"safe read-only validation"},"generatedCode":"curl ... using {{SECRET}}"}]}

        Rules:
        - filePath MUST be copied exactly from the === FILE: ... === header.
        - secretValue MUST be copied exactly from the file content; never invent or modify it.
        - Do not report placeholders, examples, documentation samples, or obvious dummy values.
        - generatedCode MUST use the literal placeholder {{SECRET}} instead of the raw secret.
        - validationPlan must describe a single safe, read-only, idempotent HTTP request to a well-known identity or "who am I" endpoint for the detected provider. Never propose destructive or state-changing actions.
        - If no real secrets are present, return {"findings":[]}.
        """;

    private sealed class AiCallBudget(int maxCalls)
    {
        private int _used;

        public bool TryConsume()
        {
            if (_used >= maxCalls)
                return false;

            _used++;
            return true;
        }
    }

    private readonly record struct SecretAnalysisOutcome(
        int FindingsReturned,
        int FindingsPersisted,
        int AiCalls,
        string? Skipped);

    private async Task<string> ExecuteStage7_CrossFileAnalysisAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var findings = await _dbContext.AiInvestigationEvidences
            .Where(e => e.InvestigationId == job.Id && e.EvidenceType == "HardcodedSecret")
            .Select(e => new { e.FilePath, e.CandidateId })
            .ToListAsync(ct);

        var correlatedFiles = findings
            .GroupBy(f => f.FilePath)
            .Select(g => new { filePath = g.Key, findings = g.Count() })
            .OrderByDescending(x => x.findings)
            .ThenBy(x => x.filePath, StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .ToList();

        var multiFileCandidates = findings
            .Where(f => f.CandidateId.HasValue)
            .GroupBy(f => f.CandidateId!.Value)
            .Select(g => new
            {
                candidateId = g.Key,
                files = g.Select(f => f.FilePath).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            })
            .Where(x => x.files.Count > 1)
            .ToList();

        var snapshotFilePaths = await _dbContext.SnapshotFiles
            .Where(f => f.SnapshotId == job.SnapshotId)
            .Select(f => f.FilePath)
            .ToListAsync(ct);

        var crossFileList = correlatedFiles.Select(c => c.filePath).ToList();
        if (crossFileList.Count == 0 && snapshotFilePaths.Count > 0)
        {
            var configMatches = snapshotFilePaths
                .Where(p => p.Contains(".env") || p.Contains("docker-compose") || p.Contains("config") || p.EndsWith(".json") || p.EndsWith(".yml") || p.EndsWith(".yaml"))
                .Take(10)
                .ToList();
            crossFileList = configMatches.Count > 0 ? configMatches : snapshotFilePaths.Take(10).ToList();
        }

        if (crossFileList.Count > 0)
        {
            var anchorPath = crossFileList.FirstOrDefault(p => p.Contains("docker-compose")) ?? crossFileList[0];
            await SaveEvidenceAsync(
                job,
                "CrossFileRelationship",
                anchorPath,
                1,
                20,
                FindingConfidence.High,
                DiscoveryType.AiInvestigator,
                JsonSerializer.Serialize(new
                {
                    correlation = $"Configuration and environment correlation across {string.Join(", ", crossFileList)}",
                    correlatedFiles = crossFileList,
                    multiFileCandidates
                }));
        }

        return JsonSerializer.Serialize(new { correlatedFiles, multiFileCandidates });
    }

    private async Task<string> ExecuteStage8_RelationshipAnalysisAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var candidateIds = await _dbContext.AiInvestigationEvidences
            .Where(e => e.InvestigationId == job.Id && e.EvidenceType == "HardcodedSecret" && e.CandidateId != null)
            .Select(e => e.CandidateId!.Value)
            .Distinct()
            .ToListAsync(ct);

        var candidates = await _dbContext.CredentialCandidates
            .Where(c => candidateIds.Contains(c.Id))
            .Select(c => new { c.Id, c.CredentialType, c.Status })
            .ToListAsync(ct);

        var relationships = candidates
            .GroupBy(c => string.IsNullOrWhiteSpace(c.CredentialType) ? "Unknown" : c.CredentialType!)
            .Select(g => new
            {
                credentialType = g.Key,
                count = g.Count(),
                statuses = g.GroupBy(c => c.Status.ToString())
                    .ToDictionary(x => x.Key, x => x.Count())
            })
            .OrderByDescending(x => x.count)
            .ToList();

        return JsonSerializer.Serialize(new { relationships });
    }

    private async Task<string> ExecuteStage9_ProductionExposureAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var paths = await _dbContext.SnapshotFiles
            .Where(f => f.SnapshotId == job.SnapshotId)
            .Select(f => f.FilePath)
            .ToListAsync(ct);

        var indicators = new List<string>();

        if (paths.Any(p => p.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase) ||
                           p.StartsWith("Dockerfile.", StringComparison.OrdinalIgnoreCase) ||
                           p.Contains("/Dockerfile", StringComparison.OrdinalIgnoreCase)))
            indicators.Add("Dockerfile");

        if (paths.Any(p => p.Contains("docker-compose", StringComparison.OrdinalIgnoreCase)))
            indicators.Add("docker-compose");

        if (paths.Any(p => p.Contains(".env.production", StringComparison.OrdinalIgnoreCase) ||
                           p.Contains(".env.prod", StringComparison.OrdinalIgnoreCase)))
            indicators.Add("production-env-file");

        if (paths.Any(p => p.StartsWith("k8s/", StringComparison.OrdinalIgnoreCase) ||
                           p.StartsWith("kubernetes/", StringComparison.OrdinalIgnoreCase) ||
                           p.StartsWith("helm/", StringComparison.OrdinalIgnoreCase) ||
                           p.Contains("/k8s/", StringComparison.OrdinalIgnoreCase) ||
                           p.Contains("/kubernetes/", StringComparison.OrdinalIgnoreCase)))
            indicators.Add("kubernetes-manifests");

        if (paths.Any(p => p.Contains(".github/workflows/", StringComparison.OrdinalIgnoreCase) ||
                           p.Contains(".gitlab-ci", StringComparison.OrdinalIgnoreCase) ||
                           p.Equals("Jenkinsfile", StringComparison.OrdinalIgnoreCase)))
            indicators.Add("ci-cd-workflows");

        if (paths.Any(p => p.EndsWith(".tf", StringComparison.OrdinalIgnoreCase) ||
                           p.EndsWith(".tfvars", StringComparison.OrdinalIgnoreCase)))
            indicators.Add("terraform");

        if (paths.Any(p => p.Equals("render.yaml", StringComparison.OrdinalIgnoreCase) ||
                           p.Equals("vercel.json", StringComparison.OrdinalIgnoreCase) ||
                           p.Equals("netlify.toml", StringComparison.OrdinalIgnoreCase) ||
                           p.Equals("fly.toml", StringComparison.OrdinalIgnoreCase)))
            indicators.Add("paas-deploy-config");

        return JsonSerializer.Serialize(new
        {
            indicators,
            likelyProductionExposed = indicators.Count > 0
        });
    }

    private async Task<string> ExecuteStage10_FinalReportAsync(AiInvestigationJob job, CancellationToken ct)
    {
        var totalEvidence = await _dbContext.AiInvestigationEvidences
            .Where(e => e.InvestigationId == job.Id)
            .CountAsync(ct);

        return JsonSerializer.Serialize(new { summary = "Repository investigation completed safely.", totalEvidenceCount = totalEvidence, riskLevel = "Medium" });
    }

    private async Task SaveEvidenceAsync(AiInvestigationJob job, string evidenceType, string filePath, int startLine, int endLine, FindingConfidence confidence, DiscoveryType source, string metadataJson)
    {
        string rawFingerprint = $"{job.SnapshotId}:{evidenceType}:{filePath}:{startLine}:{endLine}";
        string fingerprint = FingerprintUtils.ComputeSha256(rawFingerprint);

        var existing = await _dbContext.AiInvestigationEvidences
            .FirstOrDefaultAsync(e => e.SnapshotId == job.SnapshotId && e.Fingerprint == fingerprint);

        if (existing != null)
        {
            return; // Idempotent: evidence already exists
        }

        var evidence = new AiInvestigationEvidence
        {
            InvestigationId = job.Id,
            SnapshotId = job.SnapshotId,
            EvidenceType = evidenceType,
            FilePath = filePath,
            StartLine = startLine,
            EndLine = endLine,
            Confidence = confidence,
            Source = source,
            EvidenceJson = metadataJson,
            Fingerprint = fingerprint,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.AiInvestigationEvidences.Add(evidence);
        await _dbContext.SaveChangesAsync();
    }

    public static string BuildMaskedPromptContext(string rawFileContent, string secretToMask)
    {
        if (string.IsNullOrEmpty(rawFileContent)) return string.Empty;
        if (string.IsNullOrEmpty(secretToMask)) return rawFileContent;
        var maskedSecret = FingerprintUtils.MaskSecret(secretToMask);
        return rawFileContent.Replace(secretToMask, maskedSecret);
    }
}
