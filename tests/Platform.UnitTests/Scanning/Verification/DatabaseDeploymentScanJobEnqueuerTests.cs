using System;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Verification.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning.Verification;

/// <summary>
/// Unit tests for <see cref="DatabaseDeploymentScanJobEnqueuer"/>.
/// Uses an EF Core in-memory database — no real PostgreSQL required.
/// </summary>
public class DatabaseDeploymentScanJobEnqueuerTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly DatabaseDeploymentScanJobEnqueuer _enqueuer;

    private static readonly Guid TestTenantId = Guid.NewGuid();

    private static readonly DeploymentTargetResolution ValidResolution = new(
        TenantId: TestTenantId,
        ApplicationId: "app-enqueuer-test",
        AuthorizedTargetUrl: "https://api.example.com",
        Environment: "Production",
        IsAuthorized: true);

    private static readonly DeploymentWebhookRequest ValidRequest = new(
        ApplicationId: "app-enqueuer-test",
        DeploymentId: "dep-999",
        CommitSha: "deadbeef",
        Environment: "Production",
        DeployedAtUtc: DateTime.UtcNow);

    public DatabaseDeploymentScanJobEnqueuerTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("DeploymentEnqueuerTestDb_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _enqueuer = new DatabaseDeploymentScanJobEnqueuer(
            _dbContext,
            NullLogger<DatabaseDeploymentScanJobEnqueuer>.Instance);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task EnqueueDeploymentScan_ValidInput_PersistsQueuedScanJob()
    {
        var jobId = await _enqueuer.EnqueueDeploymentScanAsync(ValidResolution, ValidRequest);

        Assert.NotEqual(Guid.Empty, jobId);

        var job = await _dbContext.SecurityScanJobs.FirstOrDefaultAsync(j => j.Id == jobId);
        Assert.NotNull(job);
        Assert.Equal(SecurityScanJobStatus.Queued, job!.Status);
        Assert.Equal(ValidResolution.TenantId, job.TenantId);
        Assert.Equal(ValidResolution.AuthorizedTargetUrl, job.TargetUrl);
    }

    [Fact]
    public async Task EnqueueDeploymentScan_UsesAuthorizedTargetUrl_NotCallerProvidedUrl()
    {
        // The enqueuer must use the server-authoritative URL from the resolved application
        // registration — it never reads a URL from the request payload.
        var maliciousResolution = new DeploymentTargetResolution(
            TenantId: TestTenantId,
            ApplicationId: ValidResolution.ApplicationId,
            AuthorizedTargetUrl: "https://api.example.com",
            Environment: ValidResolution.Environment,
            IsAuthorized: true);

        var jobId = await _enqueuer.EnqueueDeploymentScanAsync(maliciousResolution, ValidRequest);

        var job = await _dbContext.SecurityScanJobs.FirstAsync(j => j.Id == jobId);
        Assert.Equal("https://api.example.com", job.TargetUrl);
    }

    [Fact]
    public async Task EnqueueDeploymentScan_TriggeredByCiCdWebhook()
    {
        var jobId = await _enqueuer.EnqueueDeploymentScanAsync(ValidResolution, ValidRequest);

        var job = await _dbContext.SecurityScanJobs.FirstAsync(j => j.Id == jobId);
        Assert.Equal("CiCdWebhook", job.TriggeredBy);
        Assert.Null(job.RequestedByUserId); // System-initiated — no user
    }

    [Fact]
    public async Task EnqueueDeploymentScan_NullResolution_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _enqueuer.EnqueueDeploymentScanAsync(null!, ValidRequest));
    }

    [Fact]
    public async Task EnqueueDeploymentScan_NullRequest_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _enqueuer.EnqueueDeploymentScanAsync(ValidResolution, null!));
    }

    [Fact]
    public async Task EnqueueDeploymentScan_EmptyTenantId_Throws()
    {
        var badResolution = new DeploymentTargetResolution(
            TenantId: Guid.Empty,
            ApplicationId: ValidResolution.ApplicationId,
            AuthorizedTargetUrl: ValidResolution.AuthorizedTargetUrl,
            Environment: ValidResolution.Environment,
            IsAuthorized: true);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enqueuer.EnqueueDeploymentScanAsync(badResolution, ValidRequest));
    }

    [Fact]
    public async Task EnqueueDeploymentScan_EmptyTargetUrl_Throws()
    {
        var badResolution = new DeploymentTargetResolution(
            TenantId: TestTenantId,
            ApplicationId: ValidResolution.ApplicationId,
            AuthorizedTargetUrl: "",
            Environment: ValidResolution.Environment,
            IsAuthorized: true);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _enqueuer.EnqueueDeploymentScanAsync(badResolution, ValidRequest));
    }

    [Fact]
    public async Task EnqueueDeploymentScan_ReturnsUniqueJobIds_ForEachInvocation()
    {
        var id1 = await _enqueuer.EnqueueDeploymentScanAsync(ValidResolution, ValidRequest);
        var id2 = await _enqueuer.EnqueueDeploymentScanAsync(ValidResolution, ValidRequest);

        Assert.NotEqual(Guid.Empty, id1);
        Assert.NotEqual(Guid.Empty, id2);
        Assert.NotEqual(id1, id2);
    }
}
