using System.Net;
using Microsoft.AspNetCore.DataProtection;
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

public class AiInvestigationEngineTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAiModelRouter> _mockRouter;
    private readonly Mock<ILogger<AiInvestigationEngine>> _mockLogger;

    public AiInvestigationEngineTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AiEngineTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        _mockRouter = new Mock<IAiModelRouter>();
        _mockLogger = new Mock<ILogger<AiInvestigationEngine>>();

        _mockRouter
            .Setup(r => r.ExecuteWithFallbackAsync(It.IsAny<AiPromptRequest>(), It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
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
        var repo = new Repository { FullName = "octocat/security-demo" };

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
            Status = JobStatus.Queued
        };

        _dbContext.Repositories.Add(repo);
        _dbContext.RepositorySnapshots.Add(snapshot);
        _dbContext.AiInvestigationJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        return (repo, snapshot, job);
    }

    [Fact]
    public async Task ExecuteInvestigation_ExecutesAllStages_AndSavesCheckpointsAndEvidences()
    {
        var (repo, snapshot, job) = await SeedJobAsync();
        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);

        await engine.ExecuteInvestigationAsync(job.Id);

        var updatedJob = await _dbContext.AiInvestigationJobs
            .Include(j => j.Checkpoints)
            .Include(j => j.Evidences)
            .FirstAsync(j => j.Id == job.Id);

        Assert.Equal(JobStatus.Succeeded, updatedJob.Status);
        Assert.Equal(10, updatedJob.CompletedStagesCount);
        Assert.Equal(10, updatedJob.Checkpoints.Count);
        Assert.NotEmpty(updatedJob.Evidences);
    }

    [Fact]
    public async Task ExecuteInvestigation_RestartSafe_ResumesFromUncompletedStageWithoutReexecutingFinishedStages()
    {
        var (repo, snapshot, job) = await SeedJobAsync();

        // Simulate crash: First 3 stages already checkpointed
        _dbContext.AiInvestigationCheckpoints.AddRange(
            new AiInvestigationCheckpoint { InvestigationJobId = job.Id, StageType = AiInvestigationStageType.RepositoryMetadata, DurableResultJson = "{}" },
            new AiInvestigationCheckpoint { InvestigationJobId = job.Id, StageType = AiInvestigationStageType.FileInventory, DurableResultJson = "{}" },
            new AiInvestigationCheckpoint { InvestigationJobId = job.Id, StageType = AiInvestigationStageType.TechnologyIdentification, DurableResultJson = "{}" }
        );
        job.CompletedStagesCount = 3;
        await _dbContext.SaveChangesAsync();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);
        await engine.ExecuteInvestigationAsync(job.Id);

        var updatedJob = await _dbContext.AiInvestigationJobs.Include(j => j.Checkpoints).FirstAsync(j => j.Id == job.Id);
        Assert.Equal(JobStatus.Succeeded, updatedJob.Status);
        Assert.Equal(10, updatedJob.CompletedStagesCount);
        Assert.Equal(10, updatedJob.Checkpoints.Count);
    }

    [Fact]
    public async Task ExecuteInvestigation_GlobalPause_PausesJobSafelyAtStageBoundary()
    {
        var (repo, snapshot, job) = await SeedJobAsync();
        _dbContext.SystemSettings.Add(new SystemSetting { Key = "ai.global_enabled", Value = "false", ValueType = SettingValueType.Boolean });
        await _dbContext.SaveChangesAsync();

        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);
        await engine.ExecuteInvestigationAsync(job.Id);

        var updatedJob = await _dbContext.AiInvestigationJobs.FirstAsync(j => j.Id == job.Id);
        Assert.Equal(JobStatus.Paused, updatedJob.Status);
    }

    [Fact]
    public async Task ExecuteInvestigation_Idempotency_EvidenceWithSameFingerprintIsNotDuplicated()
    {
        var (repo, snapshot, job) = await SeedJobAsync();
        var engine = new AiInvestigationEngine(_dbContext, _mockRouter.Object, _mockLogger.Object);

        // Execute twice
        await engine.ExecuteInvestigationAsync(job.Id);
        var initialEvidencesCount = await _dbContext.AiInvestigationEvidences.CountAsync(e => e.InvestigationId == job.Id);

        // Reset job status to re-run
        job.Status = JobStatus.Queued;
        job.Checkpoints.Clear();
        job.CompletedStagesCount = 0;
        await _dbContext.SaveChangesAsync();

        await engine.ExecuteInvestigationAsync(job.Id);
        var reRunEvidencesCount = await _dbContext.AiInvestigationEvidences.CountAsync(e => e.InvestigationId == job.Id);

        Assert.Equal(initialEvidencesCount, reRunEvidencesCount);
    }
}
