using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Application.Common;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.IntegrationTests.Scanning;

public class HostedScanWorkerIntegrationTests
{
    private class TestUserContext : ICurrentUserContext
    {
        public Guid? UserId { get; set; } = Guid.Parse("ade4b0fc-dd14-498d-af34-2d7151b8a142");
        public string? SessionId { get; set; } = "session-123";
        public bool IsAuthenticated { get; set; } = true;
        public bool IsPlatformAdmin { get; set; } = true;
        public string CorrelationId { get; set; } = "correlation-123";
        public string IpAddress { get; set; } = "127.0.0.1";
    }

    [Fact]
    public async Task HostedScanJob_UsesRegisteredToolExecutable()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Authorized Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("amass", "Amass Scanner", "v4.0.0", true, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing }, executable: "amass");

        var job = new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        };
        db.SecurityScanJobs.Add(job);
        await db.SaveChangesAsync();

        var executedExecutable = string.Empty;
        Func<string, IGenericCliToolAdapter> factory = toolKey =>
        {
            var mockAdapter = new Mock<IGenericCliToolAdapter>();
            mockAdapter.Setup(a => a.ToolKey).Returns(toolKey);
            mockAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                       .Callback<ToolExecutionRequest, ProviderSecretLease, string, CancellationToken>((req, _, _, _) => executedExecutable = req.Executable ?? req.ToolKey)
                       .ReturnsAsync(new ToolExecutionResult(toolKey, "v4.0.0", ToolExecutionStatus.Success, 0, null, null));
            return mockAdapter.Object;
        };

        var worker = new GenericScanWorker(db, new InMemoryScanProviderSecretStore(), registry, factory, NullLogger<GenericScanWorker>.Instance);
        var result = await worker.ExecuteScanJobAsync(job.Id);

        result.Status.Should().Be(SecurityScanJobStatus.Completed);
        executedExecutable.Should().Be("amass");
    }

    [Fact]
    public async Task HostedScanJob_RejectsUnregisteredExecutable()
    {
        var manifestMap = new Dictionary<string, string> { ["subfinder"] = "subfinder", ["dotnet_tool"] = "dotnet" };
        Action act = () => GenericCliToolAdapter.ValidateToolExecutableWhitelist("unregistered_attacker_tool", "unregistered_attacker_tool", manifestMap);
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*is not registered in the authorized scanner tool manifest*");
    }

    [Fact]
    public async Task HostedScanJob_RejectsExecution_WhenManifestMissing()
    {
        var adapter = new GenericCliToolAdapter("subfinder", NullLogger<GenericCliToolAdapter>.Instance);
        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v1.0",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(5),
            Executable: "subfinder",
            AuthorizedManifest: null
        );

        using var lease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));
        Func<Task> act = async () => await adapter.ExecuteAsync(request, lease, Path.GetTempPath());
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Authorized scanner tool manifest is missing or empty*");
    }

    [Fact]
    public async Task Adversarial_ToolKeyMismatch_AttackerTool_With_DotnetExecutable_RejectedBeforeProcessStart()
    {
        var adapter = new GenericCliToolAdapter("attacker_tool", NullLogger<GenericCliToolAdapter>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));
        var scratchDir = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString());

        var manifestMap = new Dictionary<string, string>
        {
            ["dotnet_tool"] = "dotnet"
        };

        // ToolKey='attacker_tool', Executable='dotnet', Manifest Map contains 'dotnet_tool' -> 'dotnet'
        var request = new ToolExecutionRequest(
            ToolKey: "attacker_tool",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10),
            Executable: "dotnet",
            AuthorizedManifest: manifestMap
        );

        Func<Task> act = async () => await adapter.ExecuteAsync(request, secretLease, scratchDir);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*ToolKey 'attacker_tool' is not registered in the authorized scanner tool manifest*");
    }

    [Fact]
    public async Task RealProcess_Adversarial_RegisteredDotnetInManifest_Succeeds_AttackerToolAbsent_RejectedBeforeProcessLaunch()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("dotnet_tool", "Dotnet Test CLI", "v10.0.0", true, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing }, executable: "dotnet");

        var adapter = new GenericCliToolAdapter("dotnet_tool", NullLogger<GenericCliToolAdapter>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));
        var scratchDir = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString());

        var manifestMap = await registry.GetAuthorizedManifestMapAsync();

        // 1. Authorized ToolKey='dotnet_tool' with Executable='dotnet' in manifest -> succeeds
        var authorizedRequest = new ToolExecutionRequest(
            ToolKey: "dotnet_tool",
            Version: "v10.0.0",
            Arguments: new Dictionary<string, string> { ["version"] = "" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10),
            Executable: "dotnet",
            AuthorizedManifest: manifestMap
        );
        var authorizedResult = await adapter.ExecuteAsync(authorizedRequest, secretLease, scratchDir);
        authorizedResult.Status.Should().Be(ToolExecutionStatus.Success);

        // 2. Unregistered ToolKey='attacker_tool' absent from manifest -> rejected BEFORE process launch
        var unauthorizedRequest = new ToolExecutionRequest(
            ToolKey: "attacker_tool",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10),
            Executable: "dotnet",
            AuthorizedManifest: manifestMap
        );
        Func<Task> unauthorizedAct = async () => await adapter.ExecuteAsync(unauthorizedRequest, secretLease, scratchDir);
        await unauthorizedAct.Should().ThrowAsync<InvalidOperationException>().WithMessage("*ToolKey 'attacker_tool' is not registered in the authorized scanner tool manifest*");
    }

    [Fact]
    public async Task ConfigurationOnly_AdditionOf_BrandNewExecutable_Dnsx_Authorization_Binding_Succeeds()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        // Configuration-driven addition of brand-new tool 'dnsx' with executable 'dnsx'
        await registry.RegisterToolAsync("dnsx", "DNSX Fast Resolver", "v1.1.5", true, new[] { ToolCapability.DnsResolution }, executable: "dnsx");

        var authorizedManifestMap = await registry.GetAuthorizedManifestMapAsync();
        authorizedManifestMap.Should().ContainKey("dnsx");
        authorizedManifestMap["dnsx"].Should().Be("dnsx");

        // Validate binding helper succeeds for new tool without adapter code edits
        Action act = () => GenericCliToolAdapter.ValidateToolExecutableWhitelist("dnsx", "dnsx", authorizedManifestMap);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task RealProcess_ConfigurationOnly_AdditionOf_BrandNewExecutable_Succeeds()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        // Register new tool key 'custom_dotnet' pointing to harmless executable 'dotnet'
        await registry.RegisterToolAsync("custom_dotnet", "Custom Dotnet Runner", "v1.0.0", true, new[] { ToolCapability.HttpProbing }, executable: "dotnet");

        var adapter = new GenericCliToolAdapter("custom_dotnet", NullLogger<GenericCliToolAdapter>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));
        var scratchDir = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString());

        var authorizedManifestMap = await registry.GetAuthorizedManifestMapAsync();

        var request = new ToolExecutionRequest(
            ToolKey: "custom_dotnet",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string> { ["version"] = "" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10),
            Executable: "dotnet",
            AuthorizedManifest: authorizedManifestMap
        );

        var result = await adapter.ExecuteAsync(request, secretLease, scratchDir);
        result.Status.Should().Be(ToolExecutionStatus.Success);
    }

    [Fact]
    public async Task MissingExecutable_NeverFallsBackToToolKey_AndFailsClosed()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        // Manually insert entity into DB with blank Executable to simulate legacy/unconfigured entity
        var entity = new SecurityScanTool
        {
            Id = Guid.NewGuid(),
            ToolKey = "legacy_tool",
            DisplayName = "Legacy Tool",
            Version = "v1.0",
            Executable = "",
            Enabled = true,
            Required = false,
            CapabilitiesJson = "[\"HttpProbing\"]",
            HealthStatus = ToolHealthStatus.Healthy,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        };
        db.SecurityScanTools.Add(entity);
        await db.SaveChangesAsync();

        // 1. GetAuthorizedManifestMapAsync must NOT include tool with blank Executable (no fallback to ToolKey)
        var manifestMap = await registry.GetAuthorizedManifestMapAsync();
        manifestMap.Should().NotContainKey("legacy_tool");

        // 2. GenericCliToolAdapter must return TOOL_EXECUTABLE_NOT_CONFIGURED if request.Executable is missing/blank
        var adapter = new GenericCliToolAdapter("legacy_tool", NullLogger<GenericCliToolAdapter>.Instance);
        using var secretLease = new ProviderSecretLease("bughunter", new Dictionary<string, string>(), TimeSpan.FromMinutes(5));
        var request = new ToolExecutionRequest(
            ToolKey: "legacy_tool",
            Version: "v1.0",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(5),
            Executable: "",
            AuthorizedManifest: manifestMap
        );

        var result = await adapter.ExecuteAsync(request, secretLease, Path.GetTempPath());
        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("TOOL_EXECUTABLE_NOT_CONFIGURED");
    }

    [Fact]
    public async Task HostedScanJob_RejectsOutOfScopeTarget()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Authorized Target", BaseUrl = "https://authorized.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://unauthorized-evil.com", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>()
           .WithMessage("*out of scope*");
    }

    [Fact]
    public async Task HostedScanJob_CleansScratchDirectoryAfterExecution()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("subfinder", "Subfinder Tool", "v2.0.0", true, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing }, executable: "subfinder");

        var jobId = Guid.NewGuid();
        var job = new SecurityScanJob
        {
            Id = jobId,
            TargetUrl = "https://example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        };
        db.SecurityScanJobs.Add(job);
        await db.SaveChangesAsync();

        string createdScratchDir = string.Empty;
        Func<string, IGenericCliToolAdapter> factory = toolKey =>
        {
            var mockAdapter = new Mock<IGenericCliToolAdapter>();
            mockAdapter.Setup(a => a.ToolKey).Returns(toolKey);
            mockAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                       .Callback<ToolExecutionRequest, ProviderSecretLease, string, CancellationToken>((_, _, scratch, _) => createdScratchDir = scratch)
                       .ReturnsAsync(new ToolExecutionResult(toolKey, "v2.0.0", ToolExecutionStatus.Success, 0, null, null));
            return mockAdapter.Object;
        };

        var worker = new GenericScanWorker(db, new InMemoryScanProviderSecretStore(), registry, factory, NullLogger<GenericScanWorker>.Instance);
        var result = await worker.ExecuteScanJobAsync(jobId);

        result.Status.Should().Be(SecurityScanJobStatus.Completed);
        createdScratchDir.Should().NotBeNullOrEmpty();
        Directory.Exists(createdScratchDir).Should().BeFalse("Worker must clean up scratch directory after execution");
    }

    [Fact]
    public async Task HostedScanJob_CancelsAndKillsProcessTree()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("ping_tool", "Ping Long Runner", "v1.0.0", true, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing }, executable: "ping");

        var jobId = Guid.NewGuid();
        var job = new SecurityScanJob
        {
            Id = jobId,
            TargetUrl = "127.0.0.1",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        };
        db.SecurityScanJobs.Add(job);
        await db.SaveChangesAsync();

        using var cts = new CancellationTokenSource();
        CancellationTestCliToolAdapter? cancellationAdapter = null;

        Func<string, IGenericCliToolAdapter> realAdapterFactory = toolKey =>
        {
            cancellationAdapter = new CancellationTestCliToolAdapter(toolKey, NullLogger<GenericCliToolAdapter>.Instance);
            return cancellationAdapter;
        };

        var worker = new GenericScanWorker(db, new InMemoryScanProviderSecretStore(), registry, realAdapterFactory, NullLogger<GenericScanWorker>.Instance);

        var workerTask = worker.ExecuteScanJobAsync(jobId, cts.Token);

        // Deterministic synchronization: Wait for real process to start
        var liveProcess = await cancellationAdapter!.ProcessStartedTask;
        liveProcess.Should().NotBeNull();
        liveProcess.HasExited.Should().BeFalse("Real process must be running prior to cancellation");

        // Cancel execution token while real process is actively executing
        cts.Cancel();

        var result = await workerTask;

        // Verify worker status
        result.Status.Should().Be(SecurityScanJobStatus.Failed);
        result.FailureReason.Should().Contain("CANCELLED");

        // Verify actual process termination
        Func<bool> processIsTerminated = () =>
        {
            try
            {
                liveProcess.Refresh();
                return liveProcess.HasExited;
            }
            catch
            {
                return true;
            }
        };

        processIsTerminated().Should().BeTrue("Child process tree must be terminated after cancellation");
    }

    [Fact]
    public async Task RealProcess_FullChain_SecurityScanToolExecutable_To_ProcessStartInfo()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "version", Enabled = true });
        await db.SaveChangesAsync();

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("dotnet_tool", "Dotnet Test CLI", "v10.0.0", false, new[] { ToolCapability.SubdomainEnumeration, ToolCapability.DnsResolution, ToolCapability.HttpProbing }, executable: "dotnet");

        var jobId = Guid.NewGuid();
        var job = new SecurityScanJob
        {
            Id = jobId,
            TargetUrl = "version",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        };
        db.SecurityScanJobs.Add(job);
        await db.SaveChangesAsync();

        RecordingCliToolAdapter? recordingAdapter = null;
        Func<string, IGenericCliToolAdapter> realAdapterFactory = toolKey =>
        {
            recordingAdapter = new RecordingCliToolAdapter(toolKey, NullLogger<GenericCliToolAdapter>.Instance);
            return recordingAdapter;
        };

        var worker = new GenericScanWorker(db, new InMemoryScanProviderSecretStore(), registry, realAdapterFactory, NullLogger<GenericScanWorker>.Instance);
        var result = await worker.ExecuteScanJobAsync(jobId);

        result.Status.Should().Be(SecurityScanJobStatus.Completed);
        recordingAdapter.Should().NotBeNull();
        recordingAdapter!.LastRequest.Should().NotBeNull();
        recordingAdapter.LastRequest!.Executable.Should().Be("dotnet");
        recordingAdapter.LastRequest.AuthorizedManifest.Should().ContainKey("dotnet_tool");
        recordingAdapter.LastRequest.AuthorizedManifest!["dotnet_tool"].Should().Be("dotnet");
    }

    private sealed class RecordingCliToolAdapter : IGenericCliToolAdapter
    {
        private readonly GenericCliToolAdapter _inner;

        public ToolExecutionRequest? LastRequest { get; private set; }
        public string ToolKey => _inner.ToolKey;

        public RecordingCliToolAdapter(string toolKey, ILogger<GenericCliToolAdapter> logger)
        {
            _inner = new GenericCliToolAdapter(toolKey, logger);
        }

        public async Task<ToolExecutionResult> ExecuteAsync(ToolExecutionRequest request, ProviderSecretLease secretLease, string scratchDirectory, CancellationToken cancellationToken = default)
        {
            LastRequest = request;
            return await _inner.ExecuteAsync(request, secretLease, scratchDirectory, cancellationToken);
        }
    }

    private sealed class CancellationTestCliToolAdapter : IGenericCliToolAdapter
    {
        private readonly GenericCliToolAdapter _inner;
        private readonly TaskCompletionSource<Process> _processStartedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<Process> ProcessStartedTask => _processStartedTcs.Task;
        public string ToolKey => _inner.ToolKey;

        public CancellationTestCliToolAdapter(string toolKey, ILogger<GenericCliToolAdapter> logger)
        {
            _inner = new GenericCliToolAdapter(toolKey, logger);
        }

        public async Task<ToolExecutionResult> ExecuteAsync(ToolExecutionRequest request, ProviderSecretLease secretLease, string scratchDirectory, CancellationToken cancellationToken = default)
        {
            var longRunningRequest = request with
            {
                Arguments = OperatingSystem.IsWindows()
                    ? new Dictionary<string, string> { ["-n"] = "30", ["127.0.0.1"] = "" }
                    : new Dictionary<string, string> { ["-c"] = "30", ["127.0.0.1"] = "" }
            };

            var execTask = _inner.ExecuteAsync(longRunningRequest, secretLease, scratchDirectory, cancellationToken);

            for (var i = 0; i < 50; i++)
            {
                var procs = Process.GetProcessesByName("ping");
                var active = procs.FirstOrDefault(p => !p.HasExited);
                if (active != null)
                {
                    _processStartedTcs.TrySetResult(active);
                    break;
                }
                await Task.Delay(20);
            }

            return await execTask;
        }
    }

    private static PlatformDbContext CreateInMemoryDbContext()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new PlatformDbContext(dbOptions);
    }
}
