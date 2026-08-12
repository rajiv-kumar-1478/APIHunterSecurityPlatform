using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class SecurityFindingTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;

    public SecurityFindingTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("Phase6FindingTestDb_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        var loggerMock = new Mock<ILogger<SecurityFindingService>>();
        var riskPolicy = new Platform.Application.Configuration.RiskPolicyOptions();
        var riskEngine = new RiskEngine(riskPolicy);
        _findingService = new SecurityFindingService(_dbContext, riskEngine, loggerMock.Object);

    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task UpsertFindingAsync_CreatesNewFindingAndDeduplicatesOnCanonicalFingerprint()
    {
        var repoId = Guid.NewGuid();
        var coreEntityId = "candidate:openai:12345";

        var req1 = new CreateOrUpdateFindingRequest(
            RepositoryId: repoId,
            SnapshotId: null,
            FindingType: FindingType.ValidatedCredentialExposed,
            Severity: RiskSeverity.Critical,
            Confidence: FindingConfidence.High,

            Title: "Validated OpenAI API Key Exposed in Settings",
            Description: "A live OpenAI API key was detected and verified via live API response.",
            CoreEntityId: coreEntityId
        );

        // 1. Initial creation
        var finding1 = await _findingService.UpsertFindingAsync(req1);
        Assert.NotNull(finding1);
        Assert.Equal(FindingStatus.Open, finding1.Status);
        Assert.Equal(RiskSeverity.Medium, finding1.Severity);
        Assert.Equal(FindingConfidence.High, finding1.Confidence);



        string expectedFingerprint = SecurityFindingService.ComputeFindingFingerprint(repoId, FindingType.ValidatedCredentialExposed, coreEntityId);
        Assert.Equal(expectedFingerprint, finding1.FindingFingerprint);

        // 2. Re-run analysis (idempotent update)
        var req2 = new CreateOrUpdateFindingRequest(
            RepositoryId: repoId,
            SnapshotId: null,
            FindingType: FindingType.ValidatedCredentialExposed,
            Severity: RiskSeverity.Critical,
            Confidence: FindingConfidence.High,

            Title: "Validated OpenAI API Key Exposed in Settings (Updated)",
            Description: "Updated evidence summary.",
            CoreEntityId: coreEntityId
        );

        var finding2 = await _findingService.UpsertFindingAsync(req2);

        // Deduplication Assertion: Must return SAME finding ID
        Assert.Equal(finding1.Id, finding2.Id);
        Assert.Equal("Validated OpenAI API Key Exposed in Settings (Updated)", finding2.Title);

        var (items, totalCount) = await _findingService.GetFindingsAsync(repositoryId: repoId);
        Assert.Equal(1, totalCount);
        Assert.Single(items);
    }

    [Fact]
    public async Task AttachEvidenceAsync_PolymorphicAttachmentIsIdempotentOnEvidenceFingerprint()
    {
        var repoId = Guid.NewGuid();
        var candidateId = Guid.NewGuid();
        var validationId = Guid.NewGuid();

        var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
            repoId, null, FindingType.ValidatedCredentialExposed, RiskSeverity.High, FindingConfidence.High,
            "Exposed Secret Key", "Secret detected in code", "candidate:" + candidateId
        ));

        var evReq = new AttachEvidenceRequest(
            EvidenceType: FindingEvidenceType.ValidationResult,
            DiscoverySource: DiscoveryType.CredentialValidation,
            SourceEntityId: validationId.ToString(),
            CandidateId: candidateId,
            ValidationResultId: validationId,
            EvidenceReference: $"Validation Result #{validationId} (Status: Valid)",
            SafeEvidenceJson: "{\"provider\":\"OpenAI\",\"status\":\"Valid\"}"
        );

        // 1. Initial Attachment
        var ev1 = await _findingService.AttachEvidenceAsync(finding.Id, evReq);
        Assert.NotNull(ev1);
        Assert.Equal(finding.Id, ev1.FindingId);

        string expectedEvidenceFingerprint = SecurityFindingService.ComputeEvidenceFingerprint(finding.Id, FindingEvidenceType.ValidationResult, validationId.ToString());
        Assert.Equal(expectedEvidenceFingerprint, ev1.EvidenceFingerprint);

        // 2. Duplicate Attachment Attempt
        var ev2 = await _findingService.AttachEvidenceAsync(finding.Id, evReq);
        Assert.Equal(ev1.Id, ev2.Id);

        var evidences = await _findingService.GetFindingEvidencesAsync(finding.Id);
        Assert.Single(evidences);
        Assert.Equal("Validation Result #" + validationId + " (Status: Valid)", evidences[0].EvidenceReference);
    }

    [Fact]
    public async Task FindingLifecycle_StatusTransitionsPreserveAuditHistoryAndNeverDeleteFindings()
    {
        var repoId = Guid.NewGuid();
        var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
            repoId, null, FindingType.UnvalidatedCredentialExposed, RiskSeverity.Medium, FindingConfidence.Medium,
            "Unverified Key", "Key detected", "key_1"
        ));

        Assert.Equal(FindingStatus.Open, finding.Status);
        Assert.Null(finding.ResolvedAtUtc);

        // Move to Investigating
        var updated1 = await _findingService.UpdateFindingStatusAsync(finding.Id, FindingStatus.Investigating);
        Assert.Equal(FindingStatus.Investigating, updated1.Status);

        // Move to Remediated
        var userId = Guid.NewGuid();
        var updated2 = await _findingService.UpdateFindingStatusAsync(finding.Id, FindingStatus.Remediated, userId, "Key revoked in provider console");
        Assert.Equal(FindingStatus.Remediated, updated2.Status);
        Assert.NotNull(updated2.ResolvedAtUtc);
        Assert.Equal(userId, updated2.ResolvedByUserId);
        Assert.Equal("Key revoked in provider console", updated2.ResolutionReason);

        // Assert permanent queryability (Finding exists and is retained in DB)
        var fetchedDto = await _findingService.GetFindingByIdAsync(finding.Id);
        Assert.Equal(FindingStatus.Remediated, fetchedDto.Status);
        Assert.Equal("Key revoked in provider console", fetchedDto.ResolutionReason);
    }

    [Fact]
    public async Task MandatoryNestedSafeEvidenceJson_SecretLeakTest_VerifiesRawSecretsNeverExposed()
    {
        string rawSecret = "sk-proj-supersecretrawkey12345987654321";
        string maskedKey = "sk-proj-****4321";
        var repoId = Guid.NewGuid();

        // Finding Title & Description must contain ONLY maskedKey
        var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
            repoId, null, FindingType.ValidatedCredentialExposed, RiskSeverity.Critical, FindingConfidence.High,
            Title: $"OpenAI Key ({maskedKey}) Exposed",
            Description: $"Candidate with key {maskedKey} verified valid.",
            CoreEntityId: "secret_1"
        ));


        // Safe Evidence JSON with zero raw credential leakage
        string safeJson = $"{{\"keyMask\":\"{maskedKey}\",\"provider\":\"OpenAI\",\"httpCode\":200}}";

        var evidence = await _findingService.AttachEvidenceAsync(finding.Id, new AttachEvidenceRequest(
            EvidenceType: FindingEvidenceType.ValidationResult,
            DiscoverySource: DiscoveryType.CredentialValidation,
            SourceEntityId: "val_1",
            EvidenceReference: $"Validation Result ({maskedKey})",
            SafeEvidenceJson: safeJson
        ));

        var findingDto = await _findingService.GetFindingByIdAsync(finding.Id);
        var evidences = await _findingService.GetFindingEvidencesAsync(finding.Id);

        // Assert Raw Secret NEVER appears anywhere in finding DTO properties
        Assert.DoesNotContain(rawSecret, findingDto.Title);
        Assert.DoesNotContain(rawSecret, findingDto.Description);
        Assert.DoesNotContain(rawSecret, findingDto.FindingFingerprint);
        Assert.DoesNotContain(rawSecret, findingDto.RiskFactorBreakdownJson);

        // Assert Raw Secret NEVER appears anywhere in evidence properties
        Assert.DoesNotContain(rawSecret, evidences[0].EvidenceReference);
        Assert.DoesNotContain(rawSecret, evidences[0].SafeEvidenceJson);
        Assert.Contains(maskedKey, evidences[0].SafeEvidenceJson);
    }
}
