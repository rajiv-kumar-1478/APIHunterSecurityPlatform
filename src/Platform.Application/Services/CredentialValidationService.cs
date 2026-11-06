using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public class CredentialValidationService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly IEnumerable<ICredentialValidator> _validators;
    private readonly ICredentialValidator _fallbackValidator;
    private readonly IAiValidationPlanExecutor _aiPlanExecutor;
    private readonly IDataProtector _rawProtector;
    private readonly IOptions<ValidationPolicyOptions> _policyOptions;
    private readonly ILogger<CredentialValidationService> _logger;

    public CredentialValidationService(
        IPlatformDbContext dbContext,
        IEnumerable<ICredentialValidator> validators,
        IAiValidationPlanExecutor aiPlanExecutor,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<CredentialValidationService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _validators = validators ?? throw new ArgumentNullException(nameof(validators));
        _aiPlanExecutor = aiPlanExecutor ?? throw new ArgumentNullException(nameof(aiPlanExecutor));
        _policyOptions = policyOptions ?? throw new ArgumentNullException(nameof(policyOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        if (dataProtectionProvider == null) throw new ArgumentNullException(nameof(dataProtectionProvider));
        _rawProtector = dataProtectionProvider.CreateProtector("Platform.SecretCandidate.RawValue");

        _fallbackValidator = _validators.FirstOrDefault(v => v.ProviderName == "Fallback")
            ?? throw new InvalidOperationException("FallbackCredentialValidator plugin is not registered.");
    }

    public async Task<AnalysisJob> EnqueueValidationJobAsync(Guid candidateId, CancellationToken ct = default)
    {
        var candidate = await _dbContext.CredentialCandidates
            .FirstOrDefaultAsync(c => c.Id == candidateId, ct)
            ?? throw new KeyNotFoundException($"CredentialCandidate '{candidateId}' not found.");

        // Reuse existing AnalysisJob infrastructure with JobType.CredentialValidation
        var job = new AnalysisJob
        {
            JobType = JobType.CredentialValidation,
            Status = JobStatus.Paused,
            TargetEntityType = "Candidate",
            TargetEntityId = candidate.Id,
            PayloadJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                candidateId = candidate.Id,
                providerName = candidate.CredentialType,
                requiresApproval = true,
                aiGenerated = false
            })
        };

        _dbContext.AnalysisJobs.Add(job);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("Enqueued AnalysisJob '{JobId}' for CredentialCandidate '{CandidateId}' validation.", job.Id, candidate.Id);
        return job;
    }

    public async Task<CredentialValidationResult> ValidateCandidateAsync(Guid candidateId, Guid? jobId = null, CancellationToken ct = default)
    {
        var candidate = await _dbContext.CredentialCandidates
            .FirstOrDefaultAsync(c => c.Id == candidateId, ct)
            ?? throw new KeyNotFoundException($"CredentialCandidate '{candidateId}' not found.");

        // Select appropriate validator plugin or fallback
        var validator = _validators.FirstOrDefault(v => v.ProviderName != "Fallback" && v.CanValidate(candidate))
            ?? _fallbackValidator;

        // Decrypt secret strictly within memory method scope
        string decryptedSecret = string.Empty;
        if (!string.IsNullOrWhiteSpace(candidate.EncryptedRawValue))
        {
            try
            {
                decryptedSecret = _rawProtector.Unprotect(candidate.EncryptedRawValue);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to decrypt secret for candidate '{CandidateId}'.", candidateId);
            }
        }

        // Execute validator plugin
        ValidationResultDto resultDto;
        try
        {
            resultDto = await validator.ValidateAsync(candidate, decryptedSecret, ct);
        }
        finally
        {
            // Zero secret memory string
            decryptedSecret = string.Empty;
        }

        return await RecordValidationResultAsync(
            candidate.Id,
            resultDto,
            candidate.CredentialType ?? "Unknown",
            validator.ValidatorVersion,
            jobId,
            ct);
    }

    /// <summary>
    /// Executes an admin-approved AI validation plan for a candidate and records the result.
    /// The secret is decrypted only for the duration of the request and never persisted.
    /// </summary>
    public async Task<CredentialValidationResult> ValidateWithAiPlanAsync(
        Guid candidateId,
        AiValidationPlan plan,
        string providerName,
        Guid? jobId = null,
        CancellationToken ct = default)
    {
        var candidate = await _dbContext.CredentialCandidates
            .FirstOrDefaultAsync(c => c.Id == candidateId, ct)
            ?? throw new KeyNotFoundException($"CredentialCandidate '{candidateId}' not found.");

        string decryptedSecret = string.Empty;
        if (!string.IsNullOrWhiteSpace(candidate.EncryptedRawValue))
        {
            try
            {
                decryptedSecret = _rawProtector.Unprotect(candidate.EncryptedRawValue);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to decrypt secret for candidate '{CandidateId}'.", candidateId);
            }
        }

        ValidationResultDto resultDto;
        try
        {
            resultDto = await _aiPlanExecutor.ExecuteAsync(providerName, plan, decryptedSecret, ct);
        }
        finally
        {
            decryptedSecret = string.Empty;
        }

        return await RecordValidationResultAsync(
            candidate.Id,
            resultDto,
            providerName,
            "AI-Plan-1.0",
            jobId,
            ct);
    }

    /// <summary>
    /// Persists a validation result without mutating the candidate lifecycle status.
    /// </summary>
    public async Task<CredentialValidationResult> RecordValidationResultAsync(
        Guid candidateId,
        ValidationResultDto resultDto,
        string providerName,
        string validatorVersion,
        Guid? jobId = null,
        CancellationToken ct = default)
    {
        int previousAttempts = await _dbContext.CredentialValidationResults
            .CountAsync(r => r.CandidateId == candidateId, ct);

        var valResult = new CredentialValidationResult
        {
            CandidateId = candidateId,
            ProviderName = Truncate(providerName, 100, "Unknown"),
            Status = resultDto.Status,
            Confidence = resultDto.Confidence,
            ValidatorVersion = Truncate(validatorVersion, 20, "1.0.0"),
            PolicyVersion = Truncate(_policyOptions.Value.PolicyVersion, 20, "1.0.0"),
            ResponseClassification = Truncate(resultDto.ResponseClassification, 256, string.Empty),
            SafeEvidenceJson = resultDto.SafeEvidenceJson,
            LatencyMs = resultDto.LatencyMs,
            HttpStatusCode = resultDto.HttpStatusCode,
            RetryAfterUtc = resultDto.RetryAfterUtc,
            ValidationAttemptNumber = previousAttempts + 1,
            AnalysisJobId = jobId,
            ValidatedAtUtc = DateTime.UtcNow
        };

        _dbContext.CredentialValidationResults.Add(valResult);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.CredentialRevalidationProcessed,
            ResourceType = "CredentialCandidate",
            ResourceId = candidateId.ToString(),
            Metadata = System.Text.Json.JsonSerializer.Serialize(new
            {
                providerName = valResult.ProviderName,
                validationStatus = resultDto.Status.ToString(),
                validatorVersion,
                analysisJobId = jobId
            })
        });

        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Recorded CredentialValidationResult '{ResultId}' (Status: {Status}) for Candidate '{CandidateId}' using validator '{ValidatorVersion}'.",
            valResult.Id, valResult.Status, candidateId, validatorVersion);

        return valResult;
    }

    public async Task<List<CredentialValidationResult>> GetValidationHistoryAsync(Guid candidateId, CancellationToken ct = default)
    {
        return await _dbContext.CredentialValidationResults
            .Where(r => r.CandidateId == candidateId)
            .OrderByDescending(r => r.ValidatedAtUtc)
            .ToListAsync(ct);
    }

    private static string Truncate(string? value, int maxLength, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value)) return fallback;
        return value.Length <= maxLength ? value : value[..maxLength];
    }
}
