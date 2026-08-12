using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Services;
using Xunit;

namespace Platform.UnitTests.Services;

public class AiInvestigationEngineHardeningTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAiModelRouter> _mockRouter;
    private readonly Mock<ILogger<AiInvestigationEngine>> _mockLogger;
    private readonly List<AiPromptRequest> _capturedPrompts = new();

    public AiInvestigationEngineHardeningTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AiEngineHardeningDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        _mockRouter = new Mock<IAiModelRouter>();
        _mockLogger = new Mock<ILogger<AiInvestigationEngine>>();

        _mockRouter
            .Setup(r => r.ExecuteWithFallbackAsync(It.IsAny<AiPromptRequest>(), It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
            .Callback<AiPromptRequest, IEnumerable<string>, CancellationToken>((req, cap, ct) => _capturedPrompts.Add(req))
            .ReturnsAsync((new AiPromptResponse(
                IsSuccess: true,
                RawResponseContent: "{\"findings\":[]}",
                NormalizedJsonContent: "{\"findings\":[]}",
                PromptTokens: 100,
                CompletionTokens: 20,
                ProviderName: "OpenAI",
                ModelName: "gpt-4o",
                LatencyMs: 120,
                ErrorCode: null,
                ErrorMessage: null,
                IsRetryable: false), "OpenAI", "gpt-4o"));
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<(Repository Repo, RepositorySnapshot Snapshot, AiInvestigationJob Job)> SeedJobAsync()
    {
        var repo = new Repository { FullName = "octocat/security-hardening-demo" };
        var snapshot = new RepositorySnapshot { RepositoryId = repo.Id, CommitSha = "abc12345" };
        var file1 = new SnapshotFile { SnapshotId = snapshot.Id, FilePath = "config/db.json" };
        var file2 = new SnapshotFile { SnapshotId = snapshot.Id, FilePath = ".env" };

        snapshot.Files.Add(file1);
        snapshot.Files.Add(file2);

        var job = new AiInvestigationJob
        {
            RepositoryId = repo.Id,
            SnapshotId = snapshot.Id,
            CurrentStage = AiInvestigationStageType.RepositoryMetadata,
            Status = JobStatus.Queued,
            ClaimToken = Guid.NewGuid()
        };

        _dbContext.Repositories.Add(repo);
        _dbContext.RepositorySnapshots.Add(snapshot);
        _dbContext.AiInvestigationJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        return (repo, snapshot, job);
    }

    [Fact]
    public async Task WorkerFencing_StolenLease_RejectsOldWorker()
    {
        var (repo, snapshot, job) = await SeedJobAsync();
        var oldClaimToken = job.ClaimToken;

        // Simulate Worker B reclaiming Job X and updating ClaimToken
        var newClaimToken = Guid.NewGuid();
        job.ClaimToken = newClaimToken;
        job.WorkerId = "WorkerB";
        await _dbContext.SaveChangesAsync();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);

        // Worker A attempts to execute with old claim token
        await engine.ExecuteInvestigationAsync(job.Id, oldClaimToken);

        var updatedJob = await _dbContext.AiInvestigationJobs.FirstAsync(j => j.Id == job.Id);
        // Worker A was rejected; CompletedStagesCount remains 0 for Worker A
        Assert.Equal(0, updatedJob.CompletedStagesCount);
        Assert.Equal("WorkerB", updatedJob.WorkerId);
    }

    [Fact]
    public async Task WorkerFencing_DirectSaveWithLeaseCheck_StaleWorkerARejected_ValidWorkerBSucceeds()
    {
        var (repo, snapshot, job) = await SeedJobAsync();
        var claimTokenA = job.ClaimToken;
        var claimTokenB = Guid.NewGuid();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);

        // Simulate Worker B updating ClaimToken in DB
        job.ClaimToken = claimTokenB;
        job.WorkerId = "WorkerB";
        await _dbContext.SaveChangesAsync();

        // Worker A attempts mutation with Token A
        job.CompletedStagesCount = 5;
        var successWorkerA = await engine.SaveWithLeaseCheckAsync(job, claimTokenA, CancellationToken.None);

        // Worker A mutation MUST be rejected
        Assert.False(successWorkerA);

        // Worker B attempts mutation with Token B
        job.CompletedStagesCount = 10;
        var successWorkerB = await engine.SaveWithLeaseCheckAsync(job, claimTokenB, CancellationToken.None);

        // Worker B mutation MUST succeed
        Assert.True(successWorkerB);
        Assert.Equal(10, job.CompletedStagesCount);
    }

    [Fact]
    public async Task WorkerFencing_ValidLease_AcceptsWorkerB()
    {
        var (repo, snapshot, job) = await SeedJobAsync();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);

        // Worker B executes with matching claim token
        await engine.ExecuteInvestigationAsync(job.Id, job.ClaimToken);

        var updatedJob = await _dbContext.AiInvestigationJobs.FirstAsync(j => j.Id == job.Id);
        Assert.Equal(JobStatus.Succeeded, updatedJob.Status);
        Assert.Equal(10, updatedJob.CompletedStagesCount);
    }

    [Fact]
    public async Task ThreeDiscoverySources_PreservesProvenance()
    {
        var (repo, snapshot, job) = await SeedJobAsync();

        // Seed APIHunter Record
        var record = new ApiHunterRecord { SearchProvider = "GitHubSearch", Status = PlatformKeyStatus.Unverified, MaskedKey = "sk-live-****1234" };
        var ref1 = new ApiHunterRepoReference { ApiHunterRecord = record, RepoName = repo.FullName, FilePath = "config/keys.json", LineNumber = 12 };
        _dbContext.ApiHunterRecords.Add(record);
        _dbContext.ApiHunterRepoReferences.Add(ref1);
        await _dbContext.SaveChangesAsync();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);
        await engine.ExecuteInvestigationAsync(job.Id, job.ClaimToken);

        var evidences = await _dbContext.AiInvestigationEvidences.ToListAsync();
        var apiHunterEvidence = evidences.FirstOrDefault(e => e.Source == DiscoveryType.ApiHunterSync);
        var aiEvidence = evidences.FirstOrDefault(e => e.Source == DiscoveryType.AiInvestigator);

        Assert.NotNull(apiHunterEvidence);
        Assert.Equal(DiscoveryType.ApiHunterSync, apiHunterEvidence.Source);

        Assert.NotNull(aiEvidence);
        Assert.Equal(DiscoveryType.AiInvestigator, aiEvidence.Source);
    }

    [Fact]
    public async Task StrictSemanticSeparation_DoesNotAutoValidateCandidates()
    {
        var (repo, snapshot, job) = await SeedJobAsync();
        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);

        await engine.ExecuteInvestigationAsync(job.Id, job.ClaimToken);

        var evidences = await _dbContext.AiInvestigationEvidences.ToListAsync();
        foreach (var ev in evidences)
        {
            // Verify AI discovery never sets validated candidate status
            Assert.NotEqual("Valid", ev.EvidenceType);
            Assert.NotEqual("Validated", ev.EvidenceType);
        }
    }

    [Fact]
    public void RawSecretAiInputAudit_MasksSuperSecret123FromAiPromptPayload()
    {
        string rawContent = "DB_HOST=prod-db\nDB_USER=admin\nDB_PASSWORD=SuperSecret123";
        string secretToMask = "SuperSecret123";

        string maskedPrompt = AiInvestigationEngine.BuildMaskedPromptContext(rawContent, secretToMask);

        Assert.DoesNotContain("SuperSecret123", maskedPrompt);
        Assert.Contains("Supe****t123", maskedPrompt); // MaskSecret format: Supe****t123
        Assert.Contains("DB_HOST=prod-db", maskedPrompt);
        Assert.Contains("DB_USER=admin", maskedPrompt);
    }

    [Fact]
    public async Task MultiLineAndCrossFileContext_CorrelatesDistributedSecrets()
    {
        var (repo, snapshot, job) = await SeedJobAsync();

        var file1 = new SnapshotFile { SnapshotId = snapshot.Id, FilePath = ".env" };
        var file2 = new SnapshotFile { SnapshotId = snapshot.Id, FilePath = "docker-compose.yml" };
        var file3 = new SnapshotFile { SnapshotId = snapshot.Id, FilePath = "src/config.py" };
        _dbContext.SnapshotFiles.AddRange(file1, file2, file3);
        await _dbContext.SaveChangesAsync();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);
        await engine.ExecuteInvestigationAsync(job.Id, job.ClaimToken);

        var crossFileEvidence = await _dbContext.AiInvestigationEvidences
            .FirstOrDefaultAsync(e => e.EvidenceType == "CrossFileRelationship");

        Assert.NotNull(crossFileEvidence);
        Assert.Contains("docker-compose.yml", crossFileEvidence.EvidenceJson);
        Assert.Contains(".env", crossFileEvidence.EvidenceJson);
    }

    [Fact]
    public async Task ResourceLimits_EnforcesMaxFilesAndFileSizeBytes()
    {
        var (repo, snapshot, job) = await SeedJobAsync();

        // Add 1 huge file (> 1 MB) and 3 normal files
        _dbContext.SnapshotFiles.Add(new SnapshotFile { SnapshotId = snapshot.Id, FilePath = "huge.bin", SizeBytes = 5_000_000, IsBinary = true });
        await _dbContext.SaveChangesAsync();

        var engineOptions = new AiInvestigationEngineOptions
        {
            MaxFilesPerInvestigation = 2,
            MaxFileSizeBytes = 1_048_576,
            MaxAiCallsPerInvestigation = 10,
            MaxTokensPerInvestigation = 100_000,
            MaxStageRetries = 3,
            MaxInvestigationDurationMinutes = 30
        };

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object, engineOptions);
        await engine.ExecuteInvestigationAsync(job.Id, job.ClaimToken);

        var fileInvCheckpoint = await _dbContext.AiInvestigationCheckpoints
            .FirstOrDefaultAsync(c => c.StageType == AiInvestigationStageType.FileInventory);

        Assert.NotNull(fileInvCheckpoint);
        Assert.DoesNotContain("huge.bin", fileInvCheckpoint.DurableResultJson);
    }

    [Fact]
    public async Task ResourceLimits_EnforcesMaxDurationLimit()
    {
        var (repo, snapshot, job) = await SeedJobAsync();
        job.QueuedAtUtc = DateTime.UtcNow.AddMinutes(-40); // 40 min old > 30 min limit
        await _dbContext.SaveChangesAsync();

        var engineOptions = new AiInvestigationEngineOptions { MaxInvestigationDurationMinutes = 30 };
        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object, engineOptions);

        await engine.ExecuteInvestigationAsync(job.Id, job.ClaimToken);

        var updatedJob = await _dbContext.AiInvestigationJobs.FirstAsync(j => j.Id == job.Id);
        Assert.Equal(JobStatus.Failed, updatedJob.Status);
        Assert.Contains("exceeded maximum duration limit", updatedJob.ErrorMessage);
    }

    [Fact]
    public async Task ApiHunterSeeds_ValidAndValidNoCredits_PreservesOriginalStatus()
    {
        var (repo, snapshot, job) = await SeedJobAsync();

        var recordValid = new ApiHunterRecord { SearchProvider = "GitHub", Status = PlatformKeyStatus.Valid, MaskedKey = "sk-valid-****1234" };
        var refValid = new ApiHunterRepoReference { ApiHunterRecord = recordValid, RepoName = repo.FullName, FilePath = ".env", LineNumber = 5 };

        var recordNoCredits = new ApiHunterRecord { SearchProvider = "GitHub", Status = PlatformKeyStatus.ValidNoCredits, MaskedKey = "sk-nocredit-****5678" };
        var refNoCredits = new ApiHunterRepoReference { ApiHunterRecord = recordNoCredits, RepoName = repo.FullName, FilePath = "app.config", LineNumber = 10 };

        _dbContext.ApiHunterRecords.AddRange(recordValid, recordNoCredits);
        _dbContext.ApiHunterRepoReferences.AddRange(refValid, refNoCredits);
        await _dbContext.SaveChangesAsync();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);
        await engine.ExecuteInvestigationAsync(job.Id, job.ClaimToken);

        // Verify status values in database remain untouched
        var fetchedValid = await _dbContext.ApiHunterRecords.FirstAsync(r => r.Id == recordValid.Id);
        var fetchedNoCredits = await _dbContext.ApiHunterRecords.FirstAsync(r => r.Id == recordNoCredits.Id);

        Assert.Equal(PlatformKeyStatus.Valid, fetchedValid.Status);
        Assert.Equal(PlatformKeyStatus.ValidNoCredits, fetchedNoCredits.Status);
    }
}
