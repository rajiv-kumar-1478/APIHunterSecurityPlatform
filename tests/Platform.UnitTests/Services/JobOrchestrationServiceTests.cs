using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Permissions;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class JobOrchestrationServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<IAuditService> _auditMock = new();

    public JobOrchestrationServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("JobOrchestrationTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task CreateJobAsync_AddsQueuedJobWithCorrelationId()
    {
        var service = new JobOrchestrationService(_dbContext, _auditMock.Object, NullLogger<JobOrchestrationService>.Instance);

        var job = await service.CreateJobAsync(JobType.RepositoryAcquisition, "Repository", Guid.NewGuid(), priority: 10);

        Assert.NotNull(job);
        Assert.Equal(JobStatus.Queued, job.Status);
        Assert.Equal(10, job.Priority);
        Assert.NotEmpty(job.CorrelationId);
    }

    [Fact]
    public async Task ClaimNextJobAsync_ClaimsHighestPriorityQueuedJob()
    {
        var service = new JobOrchestrationService(_dbContext, _auditMock.Object, NullLogger<JobOrchestrationService>.Instance);

        await service.CreateJobAsync(JobType.RepositoryAcquisition, "Repository", Guid.NewGuid(), priority: 10);
        var highPriorityJob = await service.CreateJobAsync(JobType.SnapshotAnalysis, "Snapshot", Guid.NewGuid(), priority: 100);

        var claimed = await service.ClaimNextJobAsync("worker-instance-1");

        Assert.NotNull(claimed);
        Assert.Equal(highPriorityJob.Id, claimed.Id);
        Assert.Equal(JobStatus.Running, claimed.Status);
        Assert.Equal("worker-instance-1", claimed.WorkerInstanceId);
    }

    [Fact]
    public async Task FailJobAsync_UnderMaxRetries_SetsStatusToRetryingWithExponentialBackoff()
    {
        var service = new JobOrchestrationService(_dbContext, _auditMock.Object, NullLogger<JobOrchestrationService>.Instance);

        var job = await service.CreateJobAsync(JobType.RepositoryAcquisition, "Repository", Guid.NewGuid(), priority: 10);
        job.Status = JobStatus.Running;
        await _dbContext.SaveChangesAsync();

        await service.FailJobAsync(job.Id, "Network error");

        var updatedJob = await _dbContext.AnalysisJobs.FirstAsync(j => j.Id == job.Id);
        Assert.Equal(JobStatus.Retrying, updatedJob.Status);
        Assert.Equal(1, updatedJob.RetryCount);
        Assert.NotNull(updatedJob.NextRetryAtUtc);
    }

    [Fact]
    public async Task SweepStaleJobsAsync_RequeuesStaleWorkerJobs()
    {
        var service = new JobOrchestrationService(_dbContext, _auditMock.Object, NullLogger<JobOrchestrationService>.Instance);

        var staleJob = new AnalysisJob
        {
            JobType = JobType.SnapshotAnalysis,
            TargetEntityType = "Snapshot",
            TargetEntityId = Guid.NewGuid(),
            Status = JobStatus.Running,
            WorkerInstanceId = "dead-worker",
            LastHeartbeatAtUtc = DateTime.UtcNow.AddMinutes(-10),
            CorrelationId = Guid.NewGuid().ToString()
        };

        _dbContext.AnalysisJobs.Add(staleJob);
        await _dbContext.SaveChangesAsync();

        var sweptCount = await service.SweepStaleJobsAsync(staleTimeoutMinutes: 5);

        Assert.Equal(1, sweptCount);
        var updatedJob = await _dbContext.AnalysisJobs.FirstAsync(j => j.Id == staleJob.Id);
        Assert.Equal(JobStatus.Retrying, updatedJob.Status);
    }
}
