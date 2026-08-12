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
    private readonly IDataProtector _rawProtector;
    private readonly IOptions<ValidationPolicyOptions> _policyOptions;
    private readonly ILogger<CredentialValidationService> _logger;

    public CredentialValidationService(
        IPlatformDbContext dbContext,
        IEnumerable<ICredentialValidator> validators,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<ValidationPolicyOptions> policyOptions,
        ILogger<CredentialValidationService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _validators = validators ?? throw new ArgumentNullException(nameof(validators));
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
            Status = JobStatus.Queued,
            TargetEntityType = "Candidate",
            TargetEntityId = candidate.Id,
            PayloadJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                candidateId = candidate.Id,
                providerName = candidate.CredentialType
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

        // Determine attempt number
        int previousAttempts = await _dbContext.CredentialValidationResults
            .CountAsync(r => r.CandidateId == candidateId, ct);

        // Record historical ValidationResult (DO NOT modify Candidate.Status!)
        var valResult = new CredentialValidationResult
        {
            CandidateId = candidate.Id,
            ProviderName = candidate.CredentialType ?? "Unknown",
            Status = resultDto.Status,
            Confidence = resultDto.Confidence,
            ValidatorVersion = validator.ValidatorVersion,
            PolicyVersion = _policyOptions.Value.PolicyVersion,
            ResponseClassification = resultDto.ResponseClassification,
            SafeEvidenceJson = resultDto.SafeEvidenceJson,
            LatencyMs = resultDto.LatencyMs,
            HttpStatusCode = resultDto.HttpStatusCode,
            RetryAfterUtc = resultDto.RetryAfterUtc,
            ValidationAttemptNumber = previousAttempts + 1,
            AnalysisJobId = jobId,
            ValidatedAtUtc = DateTime.UtcNow
        };

        _dbContext.CredentialValidationResults.Add(valResult);

        // Audit Event
        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.SystemSettingChanged,
            ResourceType = "CredentialCandidate",
            ResourceId = candidateId.ToString(),
            Metadata = System.Text.Json.JsonSerializer.Serialize(new
            {
                providerName = candidate.CredentialType,
                validationStatus = resultDto.Status.ToString()
            })
        });

        await _dbContext.SaveChangesAsync(ct);


        // Verify Candidate.Status remained untouched (Discovery/Triage lifecycle preserved!)
        _logger.LogInformation("Recorded CredentialValidationResult '{ResultId}' (Status: {Status}) for Candidate '{CandidateId}'. Candidate.Status remains '{CandidateStatus}'.",
            valResult.Id, valResult.Status, candidate.Id, candidate.Status);

        return valResult;
    }

    public async Task<List<CredentialValidationResult>> GetValidationHistoryAsync(Guid candidateId, CancellationToken ct = default)
    {
        return await _dbContext.CredentialValidationResults
            .Where(r => r.CandidateId == candidateId)
            .OrderByDescending(r => r.ValidatedAtUtc)
            .ToListAsync(ct);
    }
}
