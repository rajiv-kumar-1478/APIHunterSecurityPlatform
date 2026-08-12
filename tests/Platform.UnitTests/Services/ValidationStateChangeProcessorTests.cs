using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

/// <summary>
/// Concrete test double for SecurityIntelligenceGraphBuilder.
/// GetOrCreateNodeAsync is not virtual, so we use a subclass test double
/// rather than Moq to intercept calls.
/// </summary>
internal sealed class FakeGraphBuilder : SecurityIntelligenceGraphBuilder
{
    public int GetOrCreateNodeCallCount { get; private set; }
    private readonly SecurityIntelligenceNode _nodeToReturn;

    public FakeGraphBuilder(PlatformDbContext dbContext)
        : base(dbContext, new Mock<ILogger<SecurityIntelligenceGraphBuilder>>().Object)
    {
        _nodeToReturn = new SecurityIntelligenceNode
        {
            NodeType = IntelligenceNodeType.CredentialCandidate,
            Name = "fake-node",
            Label = "Fake Node"
        };
    }

    public override Task<SecurityIntelligenceNode> GetOrCreateNodeAsync(
        IntelligenceNodeType nodeType, string name, string label,
        Guid? relatedEntityId, string metadataJson, CancellationToken ct = default)
    {
        GetOrCreateNodeCallCount++;
        return Task.FromResult(_nodeToReturn);
    }
}

public class ValidationStateChangeProcessorTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;
    private readonly FakeGraphBuilder _fakeGraphBuilder;
    private readonly ValidationStateChangeProcessor _processor;

    public ValidationStateChangeProcessorTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ProcessorDb_" + Guid.NewGuid()).Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _findingService = new SecurityFindingService(
            _dbContext, new RiskEngine(new RiskPolicyOptions()),
            new Mock<ILogger<SecurityFindingService>>().Object);

        _fakeGraphBuilder = new FakeGraphBuilder(_dbContext);

        var opts = new ContinuousRevalidationOptions
        {
            GlobalEnabled = true, SchedulingIntervalSeconds = 300,
            MinRevalidationIntervalHours = 6, MaxCandidatesPerPass = 50,
            ResultLookbackHours = 24, StaleClaimTimeoutMinutes = 5
        };

        _processor = new ValidationStateChangeProcessor(
            _dbContext, _findingService, _fakeGraphBuilder,
            Options.Create(opts),
            new Mock<ILogger<ValidationStateChangeProcessor>>().Object);
    }

    public void Dispose() { _dbContext.Database.EnsureDeleted(); _dbContext.Dispose(); }

    private async Task<CredentialCandidate> SeedCandidateAsync(string type = "openai")
    {
        var repo = new Repository { FullName = "octocat/test-processor" };
        _dbContext.Repositories.Add(repo);

        var snapshot = new RepositorySnapshot { RepositoryId = repo.Id, CommitSha = "1234567890abcdef1234567890abcdef12345678" };
        _dbContext.RepositorySnapshots.Add(snapshot);

        var file = new SnapshotFile { SnapshotId = snapshot.Id, FilePath = "config.json" };
        _dbContext.SnapshotFiles.Add(file);

        var c = new CredentialCandidate { CredentialType = type, SecretFingerprint = Guid.NewGuid().ToString("N"), MaskedValue = "****", EncryptedRawValue = "enc" };
        _dbContext.CredentialCandidates.Add(c);

        var occurrence = new CandidateOccurrence { CandidateId = c.Id, SnapshotFileId = file.Id, LineNumber = 10 };
        _dbContext.CandidateOccurrences.Add(occurrence);

        await _dbContext.SaveChangesAsync();
        return c;
    }

    private async Task<CredentialValidationResult> SeedResultAsync(Guid candidateId, ValidationStatus status, bool processed = false, Guid? claimToken = null, DateTime? claimedAt = null)
    {
        var r = new CredentialValidationResult
        {
            CandidateId = candidateId, ProviderName = "openai", Status = status,
            ValidatedAtUtc = DateTime.UtcNow,
            ProcessedForFindingAtUtc = processed ? DateTime.UtcNow : null,
            ProcessingClaimToken = claimToken, ProcessingClaimedAtUtc = claimedAt
        };
        _dbContext.CredentialValidationResults.Add(r); await _dbContext.SaveChangesAsync(); return r;
    }

    [Fact] public async Task T1_Valid_Upserts_ValidatedCredentialExposed()
    {
        var c = await SeedCandidateAsync(); await SeedResultAsync(c.Id, ValidationStatus.Valid);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(1, report.ProcessedCount);
        Assert.NotNull(await _dbContext.SecurityFindings.FirstOrDefaultAsync(f => f.FindingType == FindingType.ValidatedCredentialExposed));
        Assert.Equal(FindingStatus.Open, (await _dbContext.SecurityFindings.FirstAsync()).Status);
    }

    [Fact] public async Task T2_ValidInsufficientScope_Upserts_ValidatedCredentialExposed()
    {
        var c = await SeedCandidateAsync(); await SeedResultAsync(c.Id, ValidationStatus.ValidInsufficientScope);
        await _processor.ProcessPendingResultsAsync();
        Assert.NotNull(await _dbContext.SecurityFindings.FirstOrDefaultAsync(f => f.FindingType == FindingType.ValidatedCredentialExposed));
    }

    [Fact] public async Task T3_Expired_Upserts_ExpiredCredentialExposed()
    {
        var c = await SeedCandidateAsync(); await SeedResultAsync(c.Id, ValidationStatus.Expired);
        await _processor.ProcessPendingResultsAsync();
        Assert.NotNull(await _dbContext.SecurityFindings.FirstOrDefaultAsync(f => f.FindingType == FindingType.ExpiredCredentialExposed));
    }

    [Fact] public async Task T4_Revoked_Upserts_RevokedCredentialExposed_Not_Expired()
    {
        var c = await SeedCandidateAsync(); await SeedResultAsync(c.Id, ValidationStatus.Revoked);
        await _processor.ProcessPendingResultsAsync();
        Assert.NotNull(await _dbContext.SecurityFindings.FirstOrDefaultAsync(f => f.FindingType == FindingType.RevokedCredentialExposed));
        Assert.Null(await _dbContext.SecurityFindings.FirstOrDefaultAsync(f => f.FindingType == FindingType.ExpiredCredentialExposed));
    }

    [Fact] public async Task T5_Invalid_MarksProcessed_NoFinding()
    {
        var c = await SeedCandidateAsync(); var r = await SeedResultAsync(c.Id, ValidationStatus.Invalid);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(1, report.ProcessedCount);
        Assert.NotNull((await _dbContext.CredentialValidationResults.FindAsync(r.Id))!.ProcessedForFindingAtUtc);
        Assert.Empty(await _dbContext.SecurityFindings.ToListAsync());
    }

    [Fact] public async Task T6_Unsupported_MarksProcessed_NoFinding()
    {
        var c = await SeedCandidateAsync(); await SeedResultAsync(c.Id, ValidationStatus.Unsupported);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(1, report.ProcessedCount); Assert.Empty(await _dbContext.SecurityFindings.ToListAsync());
    }

    [Fact] public async Task T7_BlockedByPolicy_MarksProcessed_NoFinding()
    {
        var c = await SeedCandidateAsync(); await SeedResultAsync(c.Id, ValidationStatus.BlockedByPolicy);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(1, report.ProcessedCount); Assert.Empty(await _dbContext.SecurityFindings.ToListAsync());
    }

    [Fact] public async Task T8_RateLimited_Skipped_ProcessedAtUtcNull()
    {
        var c = await SeedCandidateAsync(); var r = await SeedResultAsync(c.Id, ValidationStatus.RateLimited);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(0, report.ProcessedCount); Assert.Equal(1, report.SkippedCount);
        Assert.Null((await _dbContext.CredentialValidationResults.FindAsync(r.Id))!.ProcessedForFindingAtUtc);
    }

    [Fact] public async Task T9_Unavailable_Skipped_ProcessedAtUtcNull()
    {
        var c = await SeedCandidateAsync(); var r = await SeedResultAsync(c.Id, ValidationStatus.Unavailable);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(0, report.ProcessedCount);
        Assert.Null((await _dbContext.CredentialValidationResults.FindAsync(r.Id))!.ProcessedForFindingAtUtc);
    }

    [Fact] public async Task T10_ValidationError_Skipped_ProcessedAtUtcNull()
    {
        var c = await SeedCandidateAsync(); var r = await SeedResultAsync(c.Id, ValidationStatus.ValidationError);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(0, report.ProcessedCount);
        Assert.Null((await _dbContext.CredentialValidationResults.FindAsync(r.Id))!.ProcessedForFindingAtUtc);
    }

    [Fact] public async Task T11_AlreadyProcessed_NotReprocessed()
    {
        var c = await SeedCandidateAsync(); await SeedResultAsync(c.Id, ValidationStatus.Valid, processed: true);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(0, report.ProcessedCount); Assert.Equal(0, report.SkippedCount);
    }

    [Fact] public async Task T12_Evidence_Attached_With_ValidationResultId()
    {
        var c = await SeedCandidateAsync(); var r = await SeedResultAsync(c.Id, ValidationStatus.Valid);
        await _processor.ProcessPendingResultsAsync();
        var ev = await _dbContext.SecurityFindingEvidences.FirstOrDefaultAsync(e => e.ValidationResultId == r.Id);
        Assert.NotNull(ev); Assert.Equal(FindingEvidenceType.ValidationResult, ev.EvidenceType);
    }

    [Fact] public async Task T13_ActiveToRevoked_UpdatesGraph_EmitsAudit()
    {
        var c = await SeedCandidateAsync();
        await SeedResultAsync(c.Id, ValidationStatus.Valid, processed: true);
        await SeedResultAsync(c.Id, ValidationStatus.Revoked);
        await _processor.ProcessPendingResultsAsync();
        Assert.Equal(1, _fakeGraphBuilder.GetOrCreateNodeCallCount);
        Assert.NotNull(await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.SecurityGraphUpdated));
    }

    [Fact] public async Task T14_InactiveToActive_UpdatesGraph_EmitsAudit()
    {
        var c = await SeedCandidateAsync();
        await SeedResultAsync(c.Id, ValidationStatus.Invalid, processed: true);
        await SeedResultAsync(c.Id, ValidationStatus.Valid);
        await _processor.ProcessPendingResultsAsync();
        Assert.Equal(1, _fakeGraphBuilder.GetOrCreateNodeCallCount);
        Assert.NotNull(await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.SecurityGraphUpdated));
    }

    [Fact] public async Task T15_ActiveToActive_NoStateChange_NoGraphUpdate()
    {
        var c = await SeedCandidateAsync();
        await SeedResultAsync(c.Id, ValidationStatus.Valid, processed: true);
        await SeedResultAsync(c.Id, ValidationStatus.ValidInsufficientScope);
        await _processor.ProcessPendingResultsAsync();
        Assert.Equal(0, _fakeGraphBuilder.GetOrCreateNodeCallCount);
        Assert.Null(await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.SecurityGraphUpdated));
    }

    [Fact] public async Task T16_TransientBetweenTwoActive_NoStateChange()
    {
        var c = await SeedCandidateAsync();
        await SeedResultAsync(c.Id, ValidationStatus.Valid, processed: true);
        await SeedResultAsync(c.Id, ValidationStatus.RateLimited);
        await SeedResultAsync(c.Id, ValidationStatus.ValidInsufficientScope);
        await _processor.ProcessPendingResultsAsync();
        Assert.Equal(0, _fakeGraphBuilder.GetOrCreateNodeCallCount);
    }

    [Fact] public async Task T17_Audit_CredentialRevalidationProcessed_EmittedPerResult()
    {
        var c1 = await SeedCandidateAsync("openai"); var c2 = await SeedCandidateAsync("stripe");
        await SeedResultAsync(c1.Id, ValidationStatus.Valid); await SeedResultAsync(c2.Id, ValidationStatus.Invalid);
        await _processor.ProcessPendingResultsAsync();
        var events = await _dbContext.AuditEvents.Where(a => a.EventCode == AuditEventCode.CredentialRevalidationProcessed).ToListAsync();
        Assert.Equal(2, events.Count);
    }

    [Fact] public async Task T18_ReportCounters_Correct()
    {
        var c1 = await SeedCandidateAsync("openai"); var c2 = await SeedCandidateAsync("stripe"); var c3 = await SeedCandidateAsync("github");
        await SeedResultAsync(c1.Id, ValidationStatus.Valid);
        await SeedResultAsync(c2.Id, ValidationStatus.RateLimited);
        await SeedResultAsync(c3.Id, ValidationStatus.Invalid);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(2, report.ProcessedCount); Assert.Equal(1, report.SkippedCount); Assert.Equal(0, report.ErrorCount);
    }

    [Fact] public async Task T19_NoAutoLifecycleTransition_FindingRemainsOpen()
    {
        var c = await SeedCandidateAsync();
        await SeedResultAsync(c.Id, ValidationStatus.Valid, processed: true);
        var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(Guid.NewGuid(), null, FindingType.ValidatedCredentialExposed, RiskSeverity.High, FindingConfidence.High, "Pre-existing", "Human governed", c.Id.ToString("N")));
        await SeedResultAsync(c.Id, ValidationStatus.Revoked);
        await _processor.ProcessPendingResultsAsync();
        var reloaded = await _dbContext.SecurityFindings.FindAsync(finding.Id);
        Assert.Equal(FindingStatus.Open, reloaded!.Status); Assert.Null(reloaded.ResolvedAtUtc);
    }

    [Fact] public async Task T20_AtomicClaim_SecondWorker_Skips_ClaimedResult()
    {
        var c = await SeedCandidateAsync();
        var freshToken = Guid.NewGuid();
        var r = await SeedResultAsync(c.Id, ValidationStatus.Valid, claimToken: freshToken, claimedAt: DateTime.UtcNow);
        var report = await _processor.ProcessPendingResultsAsync();
        Assert.Equal(0, report.ProcessedCount);
        Assert.Equal(freshToken, (await _dbContext.CredentialValidationResults.FindAsync(r.Id))!.ProcessingClaimToken);
    }

    [Fact] public async Task T21_RecentTransientResult_DoesNotSuppressOverdueRevalidation()
    {
        var transients = new[] { ValidationStatus.RateLimited, ValidationStatus.Unavailable, ValidationStatus.ValidationError, ValidationStatus.Unknown, ValidationStatus.Pending };
        var definitives = new[] { ValidationStatus.Valid, ValidationStatus.ValidInsufficientScope, ValidationStatus.Expired, ValidationStatus.Revoked, ValidationStatus.Invalid, ValidationStatus.Unsupported, ValidationStatus.BlockedByPolicy };

        foreach (var s in transients) Assert.True(ValidationStateChangeProcessor.IsTransient(s), $"{s} must be transient");
        foreach (var s in definitives) Assert.False(ValidationStateChangeProcessor.IsTransient(s), $"{s} must be definitive");

        var c = await SeedCandidateAsync();
        await SeedResultAsync(c.Id, ValidationStatus.RateLimited);
        var lastDefinitive = await _dbContext.CredentialValidationResults
            .Where(r => r.CandidateId == c.Id && !transients.Contains(r.Status))
            .OrderByDescending(r => r.ValidatedAtUtc).FirstOrDefaultAsync();
        Assert.Null(lastDefinitive); // candidate treated as never-validated → overdue
    }
}
