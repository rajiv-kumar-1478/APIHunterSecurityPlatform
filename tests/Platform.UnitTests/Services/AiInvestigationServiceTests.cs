using Microsoft.EntityFrameworkCore;
using Moq;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;

using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class AiInvestigationServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<ICurrentUserContext> _mockUserContext;

    public AiInvestigationServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AiServiceTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(Guid.NewGuid());
        _mockUserContext.Setup(u => u.CorrelationId).Returns("test-corr-id");
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<(Repository Repo, RepositorySnapshot Snapshot)> SeedRepoAsync()
    {
        var repo = new Repository { FullName = "octocat/hello-world" };
        var snapshot = new RepositorySnapshot { RepositoryId = repo.Id, CommitSha = "12345678" };

        _dbContext.Repositories.Add(repo);
        _dbContext.RepositorySnapshots.Add(snapshot);
        await _dbContext.SaveChangesAsync();
        return (repo, snapshot);
    }

    [Fact]
    public async Task TriggerInvestigation_CreatesQueuedJob_AndAuditsEvent()
    {
        var (repo, snapshot) = await SeedRepoAsync();
        var service = new AiInvestigationService(_dbContext, _mockUserContext.Object);

        var result = await service.TriggerInvestigationAsync(repo.Id, snapshot.Id);

        Assert.NotNull(result);
        Assert.Equal(repo.Id, result.RepositoryId);
        Assert.Equal(snapshot.Id, result.SnapshotId);
        Assert.Equal("Queued", result.Status);

        var audit = await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.AiInvestigationTriggered);
        Assert.NotNull(audit);
    }

    [Fact]
    public async Task TriggerInvestigation_DuplicateActiveJob_ReturnsExistingJobWithoutDuplication()
    {
        var (repo, snapshot) = await SeedRepoAsync();
        var service = new AiInvestigationService(_dbContext, _mockUserContext.Object);

        var job1 = await service.TriggerInvestigationAsync(repo.Id, snapshot.Id);
        var job2 = await service.TriggerInvestigationAsync(repo.Id, snapshot.Id);

        Assert.Equal(job1.Id, job2.Id);

        var totalJobs = await _dbContext.AiInvestigationJobs.CountAsync();
        Assert.Equal(1, totalJobs);
    }

    [Fact]
    public async Task PauseResumeCancel_TransitionsStatusCorrectly()
    {
        var (repo, snapshot) = await SeedRepoAsync();
        var service = new AiInvestigationService(_dbContext, _mockUserContext.Object);

        var job = await service.TriggerInvestigationAsync(repo.Id, snapshot.Id);

        var paused = await service.PauseInvestigationAsync(job.Id);
        Assert.Equal("Paused", paused.Status);

        var resumed = await service.ResumeInvestigationAsync(job.Id);
        Assert.Equal("Queued", resumed.Status);

        var cancelled = await service.CancelInvestigationAsync(job.Id);
        Assert.Equal("Cancelled", cancelled.Status);
    }
}
