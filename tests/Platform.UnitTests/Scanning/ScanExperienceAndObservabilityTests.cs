using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Common;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanExperienceAndObservabilityTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly ScanToolRegistryService _toolRegistry;
    private readonly ToolOutputParserProvider _parserProvider;
    private readonly ScanFindingIngestionEngine _ingestionEngine;
    private readonly ScanExecutionOrchestrator _orchestrator;
    private readonly ScanJobService _scanJobService;
    private readonly TestUserContext _userContext;
    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();
    private readonly EgressTarget _egressTarget;
    private readonly ProviderSecretLease _secretLease;

    public ScanExperienceAndObservabilityTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _userContext = new TestUserContext();
        _toolRegistry = new ScanToolRegistryService(_dbContext, NullLogger<ScanToolRegistryService>.Instance);
        _parserProvider = new ToolOutputParserProvider();
        _ingestionEngine = new ScanFindingIngestionEngine(_dbContext, NullLogger<ScanFindingIngestionEngine>.Instance, new RiskEngine(new Platform.Application.Configuration.RiskPolicyOptions()));
        _orchestrator = new ScanExecutionOrchestrator(_toolRegistry, _parserProvider, _ingestionEngine, NullLogger<ScanExecutionOrchestrator>.Instance);
        _scanJobService = new ScanJobService(_dbContext, _userContext, _toolRegistry, NullLogger<ScanJobService>.Instance);

        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "test-repo",
            Url = "https://github.com/example/repo",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Example API Target",
            BaseUrl = "https://api.example.com",
            Enabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SaveChanges();

        _egressTarget = new EgressTarget(
            RawTargetUrl: "https://api.example.com",
            CanonicalHost: "api.example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { IPAddress.Parse("93.184.216.34") },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        _secretLease = new ProviderSecretLease("test-provider", new Dictionary<string, string> { ["API_KEY"] = "secret" }, TimeSpan.FromMinutes(10));
    }

    public void Dispose()
    {
        _secretLease.Dispose();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task RetryScanJob_CreatesNewQueuedJob_WithRetryLinkAndAudit()
    {
        var originalJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Failed,
            RequestedByUserId = _userContext.UserId!.Value,
            ProviderKey = "bughunter",
            FailureReason = "TOOL_CRASH",
            CreatedAtUtc = DateTime.UtcNow.AddHours(-1),
            CompletedAtUtc = DateTime.UtcNow.AddMinutes(-50)
        };

        _dbContext.SecurityScanJobs.Add(originalJob);
        await _dbContext.SaveChangesAsync();

        // Register tools required for Standard profile
        await _toolRegistry.RegisterToolAsync("nuclei", "Nuclei", "v3.0.0", true, new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning }, executable: "nuclei");

        var retriedJob = await _scanJobService.RetryScanJobAsync(originalJob.Id);

        retriedJob.Should().NotBeNull();
        retriedJob.Id.Should().NotBe(originalJob.Id);
        retriedJob.RetryOfJobId.Should().Be(originalJob.Id);
        retriedJob.Status.Should().Be(SecurityScanJobStatus.Queued);
        retriedJob.TargetUrl.Should().Be("https://api.example.com");
        retriedJob.ScanProfile.Should().Be(SecurityScanProfileType.Standard);

        var auditEvent = await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.ScanJobRetried);
        auditEvent.Should().NotBeNull();
        auditEvent!.ResourceId.Should().Be(retriedJob.Id.ToString());
    }

    [Fact]
    public async Task RetryScanJob_Rejects_WhenJobIsNotInTerminalStatus()
    {
        var runningJob = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = _userContext.UserId!.Value
        };

        _dbContext.SecurityScanJobs.Add(runningJob);
        await _dbContext.SaveChangesAsync();

        Func<Task> act = async () => await _scanJobService.RetryScanJobAsync(runningJob.Id);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Only failed, cancelled, or completed-with-warnings scan jobs can be retried*");
    }

    [Fact]
    public async Task GetJobDetail_And_GetJobReceipt_ReturnEnrichedInformation()
    {
        var receipt = new ScanExecutionReceipt(
            JobId: Guid.NewGuid(),
            Profile: SecurityScanProfileType.Standard,
            FinalJobStatus: SecurityScanJobStatus.Completed,
            StartedAtUtc: DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc: DateTime.UtcNow,
            ToolReceipts: new[]
            {
                new ToolExecutionReceipt("nuclei", "v3.0", "nuclei", "ghcr.io/nuclei", "sha256:abc", SecurityScanProfileType.Standard, ScanExecutionPhase.Assessment, ToolExecutionStatus.Success, DateTime.UtcNow.AddMinutes(-4), DateTime.UtcNow, 240000, 1024, 2, 2, 0, null, ToolFailureClassification.None)
            },
            TotalFindingsCreated: 2,
            TotalFindingsUpdated: 0,
            Summary: "Scan completed successfully."
        );

        var job = new SecurityScanJob
        {
            Id = receipt.JobId,
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Completed,
            RequestedByUserId = _userContext.UserId!.Value,
            ProgressPercentage = 100,
            CurrentPhase = "Completed",
            TotalFindingsCount = 2,
            ExecutionReceiptJson = JsonSerializer.Serialize(receipt),
            CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5),
            CompletedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityScanJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        var detail = await _scanJobService.GetJobDetailAsync(job.Id);
        detail.Should().NotBeNull();
        detail!.ProgressPercentage.Should().Be(100);
        detail.CurrentPhase.Should().Be("Completed");
        detail.ExecutionReceipt.Should().NotBeNull();
        detail.ExecutionReceipt!.ToolReceipts.Should().HaveCount(1);
        detail.ExecutionReceipt.ToolReceipts[0].ToolKey.Should().Be("nuclei");

        var retrievedReceipt = await _scanJobService.GetJobReceiptAsync(job.Id);
        retrievedReceipt.Should().NotBeNull();
        retrievedReceipt!.Summary.Should().Be("Scan completed successfully.");
    }

    [Fact]
    public async Task Orchestrator_ReportsRealTimeProgress_ViaProgressReporter()
    {
        await _toolRegistry.RegisterToolAsync(
            toolKey: "subfinder",
            displayName: "Subfinder",
            version: "v2.6.0",
            required: false,
            capabilities: new[] { ToolCapability.SubdomainEnumeration },
            executable: "subfinder"
        );

        await _toolRegistry.RegisterToolAsync(
            toolKey: "httpx",
            displayName: "HTTPX",
            version: "v1.4.0",
            required: false,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.DnsResolution },
            executable: "httpx"
        );

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Running,
            RequestedByUserId = _userContext.UserId!.Value
        };

        var mockSandbox = new MockScannerRuntimeSandbox();
        mockSandbox.RegisterToolOutput("subfinder", "{\"host\":\"api.example.com\",\"ip\":\"93.184.216.34\"}\n");
        mockSandbox.RegisterToolOutput("httpx", "{\"url\":\"https://api.example.com\",\"status_code\":200,\"title\":\"Example\"}\n");

        var progressUpdates = new List<(int Progress, ScanExecutionPhase? Phase, string? Tool)>();
        var reporter = new TestProgressReporter((jobId, pct, phase, tool, findings) =>
        {
            progressUpdates.Add((pct, phase, tool));
        });

        var receipt = await _orchestrator.ExecutePipelineAsync(job, _egressTarget, _secretLease, "C:\\scratch", mockSandbox, reporter);

        receipt.FinalJobStatus.Should().Be(SecurityScanJobStatus.Completed);
        progressUpdates.Should().NotBeEmpty();
        progressUpdates.Any(p => p.Tool == "subfinder" && p.Phase == ScanExecutionPhase.Discovery).Should().BeTrue();
        progressUpdates.Any(p => p.Tool == "httpx" && p.Phase == ScanExecutionPhase.Probing).Should().BeTrue();
        progressUpdates.Last().Progress.Should().Be(100);
    }

    private class MockScannerRuntimeSandbox : IScannerRuntimeSandbox
    {
        private readonly Dictionary<string, (ToolExecutionStatus Status, string? Output, string? ErrorCode, ToolFailureClassification FailureClassification)> _configured = new(StringComparer.OrdinalIgnoreCase);

        public void RegisterToolOutput(string toolKey, string stdout)
        {
            _configured[toolKey] = (ToolExecutionStatus.Success, stdout, null, ToolFailureClassification.None);
        }

        public Task<ToolExecutionResult> ExecuteInSandboxAsync(
            ToolExecutionRequest request,
            EgressTarget egressTarget,
            ProviderSecretLease secretLease,
            string scratchDirectory,
            CancellationToken ct = default)
        {
            if (_configured.TryGetValue(request.ToolKey, out var conf))
            {
                return Task.FromResult(new ToolExecutionResult(
                    ToolKey: request.ToolKey,
                    Version: request.Version,
                    Status: conf.Status,
                    ExitCode: conf.Status == ToolExecutionStatus.Success ? 0 : 1,
                    ArtifactReference: conf.Output,
                    ErrorCode: conf.ErrorCode,
                    FailureClassification: conf.FailureClassification
                ));
            }

            return Task.FromResult(new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: ToolExecutionStatus.Success,
                ExitCode: 0,
                ArtifactReference: null,
                ErrorCode: null,
                FailureClassification: ToolFailureClassification.None
            ));
        }
    }

    private class TestProgressReporter : IScanProgressReporter
    {
        private readonly Action<Guid, int, ScanExecutionPhase?, string?, int> _callback;

        public TestProgressReporter(Action<Guid, int, ScanExecutionPhase?, string?, int> callback)
        {
            _callback = callback;
        }

        public Task ReportProgressAsync(Guid jobId, int progressPercentage, ScanExecutionPhase? phase, string? currentTool, int findingsDiscoveredSoFar, CancellationToken ct = default)
        {
            _callback(jobId, progressPercentage, phase, currentTool, findingsDiscoveredSoFar);
            return Task.CompletedTask;
        }
    }

    private class TestUserContext : ICurrentUserContext
    {
        public Guid? UserId { get; set; } = Guid.NewGuid();
        public string? SessionId { get; set; } = "session-test";
        public bool IsAuthenticated { get; set; } = true;
        public bool IsPlatformAdmin { get; set; } = true;
        public string CorrelationId { get; set; } = "corr-test";
        public string IpAddress { get; set; } = "127.0.0.1";
    }
}
