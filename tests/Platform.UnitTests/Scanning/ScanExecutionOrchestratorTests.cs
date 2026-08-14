using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Common;
using Platform.Application.Configuration;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScanExecutionOrchestratorTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly ScanToolRegistryService _toolRegistry;
    private readonly ToolOutputParserProvider _parserProvider;
    private readonly ScanFindingIngestionEngine _ingestionEngine;
    private readonly ScanExecutionOrchestrator _orchestrator;

    private readonly Guid _repoId = Guid.NewGuid();
    private readonly Guid _targetId = Guid.NewGuid();
    private readonly EgressTarget _egressTarget;
    private readonly ProviderSecretLease _secretLease;

    public ScanExecutionOrchestratorTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new PlatformDbContext(options);
        _toolRegistry = new ScanToolRegistryService(_dbContext, NullLogger<ScanToolRegistryService>.Instance);
        _parserProvider = new ToolOutputParserProvider();

        var riskEngine = new RiskEngine(new RiskPolicyOptions());
        _ingestionEngine = new ScanFindingIngestionEngine(_dbContext, NullLogger<ScanFindingIngestionEngine>.Instance, riskEngine);

        _orchestrator = new ScanExecutionOrchestrator(
            _toolRegistry,
            _parserProvider,
            _ingestionEngine,
            NullLogger<ScanExecutionOrchestrator>.Instance
        );

        _dbContext.Repositories.Add(new Repository
        {
            Id = _repoId,
            Name = "OrchestratorTestRepo",
            FullName = "org/OrchestratorTestRepo",
            Owner = "org",
            Url = "https://github.com/org/OrchestratorTestRepo",
            CreatedAtUtc = DateTime.UtcNow
        });

        _dbContext.SecurityTargets.Add(new SecurityTarget
        {
            Id = _targetId,
            Name = "Orchestrator Target",
            TargetType = "WebEndpoint",
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
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task Orchestrator_ExecutesPhasedPipeline_ParsesOutputs_AndCreatesAuthoritativeFindings()
    {
        // 1. Register Nuclei (Assessment) and httpx (Probing) for Standard profile
        await _toolRegistry.RegisterToolAsync(
            toolKey: "httpx",
            displayName: "HTTPX Prober",
            version: "v1.4.0",
            required: false,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
            executable: "httpx"
        );

        await _toolRegistry.RegisterToolAsync(
            toolKey: "nuclei",
            displayName: "Nuclei Scanner",
            version: "v3.1.0",
            required: true,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
            executable: "nuclei"
        );

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            ProviderKey = "test-provider",
            CreatedAtUtc = DateTime.UtcNow
        };

        var mockSandbox = new MockScannerRuntimeSandbox();
        mockSandbox.RegisterToolOutput("httpx", "{\"url\":\"https://api.example.com\",\"status_code\":200,\"title\":\"API Home\",\"tech\":[\"React\"]}\n");
        mockSandbox.RegisterToolOutput("nuclei", "{\"template-id\":\"cve-2021-41773\",\"info\":{\"name\":\"Apache Path Traversal RCE\",\"severity\":\"critical\"},\"matched-at\":\"https://api.example.com/icons/.%2e/passwd\"}\n");

        var receipt = await _orchestrator.ExecutePipelineAsync(job, _egressTarget, _secretLease, "C:\\scratch", mockSandbox);

        receipt.FinalJobStatus.Should().Be(SecurityScanJobStatus.Completed);
        receipt.ToolReceipts.Should().HaveCount(2);
        receipt.TotalFindingsCreated.Should().Be(2);

        var findings = await _dbContext.SecurityFindings.Include(f => f.Evidences).ToListAsync();
        findings.Should().HaveCount(2);
        findings.Should().Contain(f => f.Title.Contains("API Home"));
        findings.Should().Contain(f => f.Title.Contains("Apache Path Traversal RCE"));
    }

    [Fact]
    public async Task Orchestrator_MultiToolFailureSemantics_PreservesSuccessfulFindings_AsCompletedWithWarnings()
    {
        // Register Tool A (succeeds) and Tool B (fails)
        await _toolRegistry.RegisterToolAsync(
            toolKey: "httpx",
            displayName: "HTTPX Prober",
            version: "v1.4.0",
            required: false,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
            executable: "httpx"
        );

        await _toolRegistry.RegisterToolAsync(
            toolKey: "nuclei",
            displayName: "Nuclei Scanner",
            version: "v3.1.0",
            required: false,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
            executable: "nuclei"
        );

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            ProviderKey = "test-provider",
            CreatedAtUtc = DateTime.UtcNow
        };

        var mockSandbox = new MockScannerRuntimeSandbox();
        // httpx succeeds
        mockSandbox.RegisterToolOutput("httpx", "{\"url\":\"https://api.example.com\",\"status_code\":200,\"title\":\"API Gateway\"}\n");
        // nuclei crashes
        mockSandbox.RegisterToolFailure("nuclei", ToolExecutionStatus.Failed, "NUCLEI_PROCESS_CRASHED");

        var receipt = await _orchestrator.ExecutePipelineAsync(job, _egressTarget, _secretLease, "C:\\scratch", mockSandbox);

        receipt.FinalJobStatus.Should().Be(SecurityScanJobStatus.CompletedWithWarnings, "Successful tool findings must be preserved when another tool fails");
        receipt.TotalFindingsCreated.Should().Be(1);

        var httpxReceipt = receipt.ToolReceipts.First(r => r.ToolKey == "httpx");
        httpxReceipt.Status.Should().Be(ToolExecutionStatus.Success);
        httpxReceipt.FindingsCreated.Should().Be(1);

        var nucleiReceipt = receipt.ToolReceipts.First(r => r.ToolKey == "nuclei");
        nucleiReceipt.Status.Should().Be(ToolExecutionStatus.Failed);
        nucleiReceipt.FailureReason.Should().Contain("NUCLEI_PROCESS_CRASHED");

        var findings = await _dbContext.SecurityFindings.ToListAsync();
        findings.Should().HaveCount(1, "Finding from successful tool must be preserved in DB");
    }

    [Fact]
    public async Task Orchestrator_FailsClosed_WhenNoCompatibleToolsAvailable()
    {
        // Register a tool that only supports SecretScanning (incompatible with Standard which requires HttpProbing, UrlCrawling, VulnerabilityScanning)
        await _toolRegistry.RegisterToolAsync(
            toolKey: "secret_scanner_only",
            displayName: "Secret Scanner Only",
            version: "v1.0.0",
            required: false,
            capabilities: new[] { ToolCapability.SecretScanning },
            executable: "trufflehog"
        );

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            ProviderKey = "test-provider",
            CreatedAtUtc = DateTime.UtcNow
        };

        var mockSandbox = new MockScannerRuntimeSandbox();
        var receipt = await _orchestrator.ExecutePipelineAsync(job, _egressTarget, _secretLease, "C:\\scratch", mockSandbox);

        receipt.FinalJobStatus.Should().Be(SecurityScanJobStatus.Failed);
        receipt.Summary.Should().Be("NO_COMPATIBLE_TOOLS_AVAILABLE");
        receipt.ToolReceipts.Should().BeEmpty();
    }

    [Fact]
    public async Task Orchestrator_PreservesImmutableProvenance_InReceiptsAndEvidence()
    {
        var tool = await _toolRegistry.RegisterToolAsync(
            toolKey: "nuclei",
            displayName: "Nuclei Scanner",
            version: "v3.1.0",
            required: true,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
            executable: "nuclei"
        );

        var toolEntity = await _dbContext.SecurityScanTools.FirstAsync(t => t.ToolKey == "nuclei");
        toolEntity.ContainerImageRepository = "ghcr.io/projectdiscovery/nuclei";
        toolEntity.ContainerImageDigest = "sha256:7b1e8e24c52084c86d8a2a8db4";
        await _dbContext.SaveChangesAsync();

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            ProviderKey = "test-provider",
            CreatedAtUtc = DateTime.UtcNow
        };

        var mockSandbox = new MockScannerRuntimeSandbox();
        mockSandbox.RegisterToolOutput("nuclei", "{\"template-id\":\"cve-2021-41773\",\"info\":{\"name\":\"Apache Path Traversal RCE\",\"severity\":\"critical\"},\"matched-at\":\"https://api.example.com/icons/.%2e/passwd\"}\n");

        var receipt = await _orchestrator.ExecutePipelineAsync(job, _egressTarget, _secretLease, "C:\\scratch", mockSandbox);

        var toolReceipt = receipt.ToolReceipts.First(r => r.ToolKey == "nuclei");
        toolReceipt.Executable.Should().Be("nuclei");
        toolReceipt.ContainerImageRepository.Should().Be("ghcr.io/projectdiscovery/nuclei");
        toolReceipt.ContainerImageDigest.Should().Be("sha256:7b1e8e24c52084c86d8a2a8db4");
        toolReceipt.StartedAtUtc.Should().BeBefore(DateTime.UtcNow.AddSeconds(1));
        toolReceipt.CompletedAtUtc.Should().BeOnOrAfter(toolReceipt.StartedAtUtc);

        var finding = await _dbContext.SecurityFindings.Include(f => f.Evidences).FirstAsync();
        var evidence = finding.Evidences.First();
        evidence.SafeEvidenceJson.Should().Contain("ghcr.io/projectdiscovery/nuclei");
        evidence.SafeEvidenceJson.Should().Contain("sha256:7b1e8e24c52084c86d8a2a8db4");
        evidence.SafeEvidenceJson.Should().Contain("nuclei");
    }

    [Fact]
    public async Task Orchestrator_FailsFast_OnSandboxFatalSecurityCrash()
    {
        await _toolRegistry.RegisterToolAsync(
            toolKey: "httpx",
            displayName: "HTTPX Prober",
            version: "v1.4.0",
            required: false,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
            executable: "httpx"
        );

        await _toolRegistry.RegisterToolAsync(
            toolKey: "nuclei",
            displayName: "Nuclei Scanner",
            version: "v3.1.0",
            required: false,
            capabilities: new[] { ToolCapability.HttpProbing, ToolCapability.UrlCrawling, ToolCapability.VulnerabilityScanning },
            executable: "nuclei"
        );

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            RepositoryId = _repoId,
            TargetId = _targetId,
            TargetUrl = "https://api.example.com",
            ScanProfile = SecurityScanProfileType.Standard,
            Status = SecurityScanJobStatus.Running,
            ProviderKey = "test-provider",
            CreatedAtUtc = DateTime.UtcNow
        };

        var mockSandbox = new MockScannerRuntimeSandbox();
        // httpx fatal sandbox crash
        mockSandbox.RegisterToolFailure("httpx", ToolExecutionStatus.Failed, "SANDBOX_CONTAINER_ESCAPED_OR_DIED");

        var receipt = await _orchestrator.ExecutePipelineAsync(job, _egressTarget, _secretLease, "C:\\scratch", mockSandbox);

        receipt.FinalJobStatus.Should().Be(SecurityScanJobStatus.Failed);
        receipt.ToolReceipts.Should().HaveCount(2);

        var httpxReceipt = receipt.ToolReceipts.First(r => r.ToolKey == "httpx");
        httpxReceipt.Status.Should().Be(ToolExecutionStatus.Failed);

        var nucleiReceipt = receipt.ToolReceipts.First(r => r.ToolKey == "nuclei");
        nucleiReceipt.Status.Should().Be(ToolExecutionStatus.Skipped, "Downstream tools must be skipped on fatal sandbox/security crash");
        nucleiReceipt.FailureReason.Should().Contain("FATAL_SECURITY_BOUNDARY_FAILURE");
    }

    private class MockScannerRuntimeSandbox : IScannerRuntimeSandbox
    {
        private readonly Dictionary<string, (ToolExecutionStatus Status, string? Output, string? ErrorCode)> _configured = new(StringComparer.OrdinalIgnoreCase);

        public void RegisterToolOutput(string toolKey, string stdout)
        {
            _configured[toolKey] = (ToolExecutionStatus.Success, stdout, null);
        }

        public void RegisterToolFailure(string toolKey, ToolExecutionStatus status, string errorCode)
        {
            _configured[toolKey] = (status, null, errorCode);
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
                    ErrorCode: conf.ErrorCode
                ));
            }

            return Task.FromResult(new ToolExecutionResult(
                ToolKey: request.ToolKey,
                Version: request.Version,
                Status: ToolExecutionStatus.Success,
                ExitCode: 0,
                ArtifactReference: "{}",
                ErrorCode: null
            ));
        }
    }
}
