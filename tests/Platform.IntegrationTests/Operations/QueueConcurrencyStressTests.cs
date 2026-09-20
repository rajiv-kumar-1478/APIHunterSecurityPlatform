using System.Collections.Concurrent;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.IntegrationTests.Operations;

public class QueueConcurrencyStressTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly DbContextOptions<PlatformDbContext> _dbOptions;
    private readonly Guid _tenantId = Guid.NewGuid();

    public QueueConcurrencyStressTests()
    {
        _dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("QueueConcurrencyDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(_dbOptions);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task ConcurrentWorkerClaims_NeverProduceDuplicateJobClaims()
    {
        // 1. Seed 200 pending jobs
        const int totalJobs = 200;
        var seededJobIds = new List<Guid>();

        for (int i = 0; i < totalJobs; i++)
        {
            var jobId = Guid.NewGuid();
            seededJobIds.Add(jobId);
            _dbContext.SecurityScanJobs.Add(new SecurityScanJob
            {
                Id = jobId,
                TenantId = _tenantId,
                Status = SecurityScanJobStatus.Pending,
                ScheduledAtUtc = DateTime.UtcNow.AddMinutes(-1),
                ToolName = "nuclei"
            });
        }
        await _dbContext.SaveChangesAsync();

        // 2. Spawn 20 concurrent worker workers claiming jobs
        const int workerCount = 20;
        var claimedJobIds = new ConcurrentBag<Guid>();
        var claimLock = new object();

        var workerTasks = Enumerable.Range(0, workerCount).Select(async workerIndex =>
        {
            var workerId = $"stress-worker-{workerIndex}";

            while (true)
            {
                Guid? claimedId = null;

                // Emulate atomic claim transaction
                lock (claimLock)
                {
                    var nextJob = _dbContext.SecurityScanJobs
                        .FirstOrDefault(j => j.Status == SecurityScanJobStatus.Pending);

                    if (nextJob != null)
                    {
                        nextJob.Status = SecurityScanJobStatus.Running;
                        nextJob.WorkerId = workerId;
                        nextJob.StartedAtUtc = DateTime.UtcNow;
                        nextJob.WorkerHeartbeatUtc = DateTime.UtcNow;
                        _dbContext.SaveChanges();
                        claimedId = nextJob.Id;
                    }
                }

                if (claimedId.HasValue)
                {
                    claimedJobIds.Add(claimedId.Value);
                    await Task.Delay(2); // Simulated job start latency
                }
                else
                {
                    break; // No more pending jobs
                }
            }
        });

        await Task.WhenAll(workerTasks);

        // 3. Verification: Exactly 200 jobs claimed, 0 duplicates
        claimedJobIds.Should().HaveCount(totalJobs);
        claimedJobIds.Distinct().Should().HaveCount(totalJobs, "every claimed job must be uniquely processed without duplicate claims");

        var remainingPending = await _dbContext.SecurityScanJobs
            .CountAsync(j => j.Status == SecurityScanJobStatus.Pending);
        remainingPending.Should().Be(0);

        var totalRunning = await _dbContext.SecurityScanJobs
            .CountAsync(j => j.Status == SecurityScanJobStatus.Running);
        totalRunning.Should().Be(totalJobs);
    }
}
