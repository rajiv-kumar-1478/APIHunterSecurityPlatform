using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Operations;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Operations;

public class IncidentEngineTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly IncidentEngineService _service;
    private readonly Guid _tenantId = Guid.NewGuid();

    public IncidentEngineTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("IncidentEngineDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _service = new IncidentEngineService(_dbContext, NullLogger<IncidentEngineService>.Instance);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task RunDetectionCycleAsync_DetectsStaleScanJobWorkerLease_RevokesLeaseAndGeneratesIncident()
    {
        // Arrange: stuck job with heartbeat > 5 minutes ago
        var stuckJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            Status = SecurityScanJobStatus.Running,
            WorkerId = "worker-node-42",
            WorkerHeartbeatUtc = DateTime.UtcNow.AddMinutes(-10),
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-12),
            RetryCount = 0
        };

        _dbContext.SecurityScanJobs.Add(stuckJob);
        await _dbContext.SaveChangesAsync();

        // Act
        await _service.RunDetectionCycleAsync();

        // Assert
        var refreshedJob = await _dbContext.SecurityScanJobs.FindAsync(stuckJob.Id);
        refreshedJob.Should().NotBeNull();
        refreshedJob!.Status.Should().Be(SecurityScanJobStatus.Pending);
        refreshedJob.WorkerId.Should().BeNull();
        refreshedJob.RetryCount.Should().Be(1);

        var incident = await _dbContext.OperationalIncidents.FirstOrDefaultAsync();
        incident.Should().NotBeNull();
        incident!.Category.Should().Be(IncidentCategory.WorkerHeartbeatLost);
        incident.Severity.Should().Be(IncidentSeverity.High);
        incident.Status.Should().Be(IncidentStatus.Mitigated);
        incident.MitigationActionTaken.Should().Contain("Autonomous self-healing");
    }

    [Fact]
    public async Task RecordOrUpdateIncidentAsync_DeduplicatesFingerprintsWithinOneHour_IncrementsOccurrenceCount()
    {
        var fingerprint = "deadlock_repo_scan_44";

        var inc1 = await _service.RecordOrUpdateIncidentAsync(
            "Deadlock on repo 44",
            fingerprint,
            IncidentCategory.LeaseDeadlock,
            IncidentSeverity.Medium,
            _tenantId);

        await _dbContext.SaveChangesAsync();

        var inc2 = await _service.RecordOrUpdateIncidentAsync(
            "Deadlock on repo 44",
            fingerprint,
            IncidentCategory.LeaseDeadlock,
            IncidentSeverity.Medium,
            _tenantId);

        await _dbContext.SaveChangesAsync();

        var incidents = await _dbContext.OperationalIncidents.ToListAsync();
        incidents.Should().HaveCount(1);
        incidents[0].OccurrenceCount.Should().Be(2);
        incidents[0].Id.Should().Be(inc1.Id);
    }

    [Fact]
    public async Task ApplyMitigationAsync_ReschedulesStalledCampaign()
    {
        var campaign = new ScanCampaign
        {
            Id = Guid.NewGuid(),
            TenantId = _tenantId,
            Name = "Nightly Continuous Scan",
            Status = ScanCampaignStatus.Active,
            NextRunUtc = DateTime.UtcNow.AddHours(-2)
        };
        _dbContext.ScanCampaigns.Add(campaign);

        var incident = new OperationalIncident
        {
            TenantId = _tenantId,
            Category = IncidentCategory.CampaignStall,
            Severity = IncidentSeverity.Medium,
            Title = "Campaign Stalled",
            Fingerprint = $"campaign_stall_{campaign.Id}",
            Status = IncidentStatus.Detected
        };
        _dbContext.OperationalIncidents.Add(incident);
        await _dbContext.SaveChangesAsync();

        var success = await _service.ApplyMitigationAsync(incident.Id, "Forced schedule recalculation");

        success.Should().BeTrue();
        var refreshedCampaign = await _dbContext.ScanCampaigns.FindAsync(campaign.Id);
        refreshedCampaign!.NextRunUtc.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));

        var refreshedIncident = await _dbContext.OperationalIncidents.FindAsync(incident.Id);
        refreshedIncident!.Status.Should().Be(IncidentStatus.Mitigated);
    }

    [Fact]
    public async Task ResolveIncidentAsync_UpdatesStatusAndNotes()
    {
        var incident = new OperationalIncident
        {
            TenantId = _tenantId,
            Category = IncidentCategory.DatabaseDegraded,
            Severity = IncidentSeverity.Critical,
            Title = "DB Connection Pool Exhaustion",
            Fingerprint = "db_pool_exhausted",
            Status = IncidentStatus.Detected
        };
        _dbContext.OperationalIncidents.Add(incident);
        await _dbContext.SaveChangesAsync();

        var resolved = await _service.ResolveIncidentAsync(incident.Id, "Scaled max pool size to 100.");

        resolved.Should().BeTrue();
        var refreshed = await _dbContext.OperationalIncidents.FindAsync(incident.Id);
        refreshed!.Status.Should().Be(IncidentStatus.Resolved);
        refreshed.ResolutionNotes.Should().Be("Scaled max pool size to 100.");
    }
}
