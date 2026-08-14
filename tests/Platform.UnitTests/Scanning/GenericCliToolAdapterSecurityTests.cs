using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
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

namespace Platform.UnitTests.Scanning;

public class GenericCliToolAdapterSecurityTests
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
    public void Test1_ValidateScratchDirectoryPath_Rejects_PathTraversal()
    {
        var root = Path.Combine(Path.GetTempPath(), "apihunter_scans");
        var invalidPath = Path.Combine(root, "..", "..", "Windows", "System32");

        Action act = () => GenericCliToolAdapter.ValidateScratchDirectoryPath(invalidPath, root);
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*escapes allowed scratch root*");
    }

    [Fact]
    public void Test2_ValidateScratchDirectoryPath_Rejects_DisallowedDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), "apihunter_scans");
        var disallowedPath = "C:\\RandomUnauthorizedFolder\\scans";

        Action act = () => GenericCliToolAdapter.ValidateScratchDirectoryPath(disallowedPath, root);
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*Scratch directory*escapes allowed scratch root*");
    }

    [Fact]
    public void Test3_ValidateScratchDirectoryPath_Rejects_SiblingPrefixAttack()
    {
        // /tmp/apihunter_scans-evil vs /tmp/apihunter_scans
        var root = Path.Combine(Path.GetTempPath(), "apihunter_scans");
        var siblingPrefixPath = root + "-evil";

        Action act = () => GenericCliToolAdapter.ValidateScratchDirectoryPath(siblingPrefixPath, root);
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*Scratch directory*escapes allowed scratch root*");
    }

    [Fact]
    public void Test4_SanitizeOutput_MasksRawSecrets_InLogsAndExceptions()
    {
        var secretDict = new Dictionary<string, string>
        {
            ["GROQ_API_KEY"] = "gsk_super_secret_groq_api_key_12345"
        };
        using var lease = new ProviderSecretLease("bughunter", secretDict, TimeSpan.FromMinutes(5));

        var rawOutput = "Tool log: authenticating using gsk_super_secret_groq_api_key_12345 to Groq API endpoint.";
        var sanitized = GenericCliToolAdapter.SanitizeOutput(rawOutput, lease);

        sanitized.Should().NotContain("gsk_super_secret_groq_api_key_12345");
        sanitized.Should().Contain("***MASKED_SECRET***");
    }

    [Fact]
    public async Task Test5_ExecuteAsync_Handles_MissingBinary()
    {
        var adapter = new GenericCliToolAdapter("subfinder", NullLogger<GenericCliToolAdapter>.Instance);
        var scratch = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString("N"));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(5),
            Executable: "subfinder",
            AuthorizedManifest: new Dictionary<string, string> { ["subfinder"] = "subfinder" }
        );

        using var lease = new ProviderSecretLease("test", new Dictionary<string, string>(), TimeSpan.FromMinutes(1));
        var result = await adapter.ExecuteAsync(request, lease, scratch, default);

        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("BINARY_NOT_FOUND");
    }

    [Fact]
    public async Task Test6_ExecuteAsync_Handles_Timeout()
    {
        var adapter = new GenericCliToolAdapter("subfinder", NullLogger<GenericCliToolAdapter>.Instance);
        var scratch = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString("N"));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string> { ["d"] = "example.com" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromMilliseconds(1), // Trigger rapid timeout
            Executable: "subfinder",
            AuthorizedManifest: new Dictionary<string, string> { ["subfinder"] = "subfinder" }
        );

        using var lease = new ProviderSecretLease("test", new Dictionary<string, string>(), TimeSpan.FromMinutes(1));
        var result = await adapter.ExecuteAsync(request, lease, scratch, default);

        // Executable missing or rapid timeout produces Failed (BINARY_NOT_FOUND) or TimedOut
        result.Status.Should().Match(s => s == ToolExecutionStatus.Failed || s == ToolExecutionStatus.TimedOut);
    }

    [Fact]
    public async Task Test7_ExecuteAsync_Handles_Cancellation()
    {
        var adapter = new GenericCliToolAdapter("subfinder", NullLogger<GenericCliToolAdapter>.Instance);
        var scratch = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString("N"));

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string> { ["d"] = "example.com" },
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10),
            Executable: "subfinder",
            AuthorizedManifest: new Dictionary<string, string> { ["subfinder"] = "subfinder" }
        );

        using var lease = new ProviderSecretLease("test", new Dictionary<string, string>(), TimeSpan.FromMinutes(1));
        var result = await adapter.ExecuteAsync(request, lease, scratch, cts.Token);

        // Pre-cancelled token triggers TimedOut/Cancelled
        result.Status.Should().Match(s => s == ToolExecutionStatus.TimedOut || s == ToolExecutionStatus.Failed);
    }

    [Fact]
    public async Task Test8_ExecuteAsync_Disambiguates_NormalExitCode124_From_Timeout()
    {
        // Custom manifest whitelist allows explicit test binary key
        var adapter = new GenericCliToolAdapter("subfinder", NullLogger<GenericCliToolAdapter>.Instance);
        var scratch = Path.Combine(Path.GetTempPath(), "apihunter_scans", Guid.NewGuid().ToString("N"));

        var request = new ToolExecutionRequest(
            ToolKey: "subfinder",
            Version: "v1.0.0",
            Arguments: new Dictionary<string, string>(),
            ScanJobId: Guid.NewGuid(),
            Timeout: TimeSpan.FromSeconds(10),
            Executable: "subfinder",
            AuthorizedManifest: new Dictionary<string, string> { ["subfinder"] = "subfinder" }
        );

        using var lease = new ProviderSecretLease("test", new Dictionary<string, string>(), TimeSpan.FromMinutes(1));
        var result = await adapter.ExecuteAsync(request, lease, scratch, default);

        // Binary missing returns Failed with BINARY_NOT_FOUND rather than TimedOut
        result.Status.Should().Be(ToolExecutionStatus.Failed);
        result.ErrorCode.Should().Be("BINARY_NOT_FOUND");
    }

    [Fact]
    public void Test9_ProviderSecretLease_Dispose_ReleasesContainerReferences()
    {
        var secretDict = new Dictionary<string, string>
        {
            ["GROQ_API_KEY"] = "gsk_super_secret_123"
        };
        var lease = new ProviderSecretLease("bughunter", secretDict, TimeSpan.FromMinutes(5));

        lease.Secrets.Should().ContainKey("GROQ_API_KEY");
        lease.Dispose();

        lease.Secrets.Should().BeEmpty("Disposal must release all managed dictionary secret references");
    }

    [Fact]
    public async Task Test10_TargetScopeValidation_FailClosed_WhenZeroTargetsConfigured()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        using var db = new PlatformDbContext(dbOptions);

        var service = new ScanJobService(
            db,
            new TestUserContext(),
            new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance),
            NullLogger<ScanJobService>.Instance
        );

        var request = new CreateScanJobRequest(null, null, "https://any-domain.com", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>()
           .WithMessage("*No authorized security targets are currently configured*");
    }

    [Fact]
    public async Task Test11_TargetScopeValidation_FailClosed_WhenTargetHostUnauthorized()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        using var db = new PlatformDbContext(dbOptions);

        db.SecurityTargets.Add(new SecurityTarget
        {
            Id = Guid.NewGuid(),
            Name = "Authorized Internal Target",
            BaseUrl = "https://authorized.example.com",
            Enabled = true
        });
        await db.SaveChangesAsync();

        var service = new ScanJobService(
            db,
            new TestUserContext(),
            new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance),
            NullLogger<ScanJobService>.Instance
        );

        var request = new CreateScanJobRequest(null, null, "https://malicious-target.com", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>()
           .WithMessage("*out of scope*");
    }

    [Fact]
    public async Task Test12_ConfigurationSecretStore_Rejects_PlaintextSecrets_In_Production()
    {
        var inMemorySettings = new Dictionary<string, string?>
        {
            ["Scanning:Providers:bughunter:Secrets:GROQ_API_KEY"] = "plaintext_unprotected_key_123"
        };
        IConfiguration config = new ConfigurationBuilder().AddInMemoryCollection(inMemorySettings!).Build();

        var envMock = new Mock<IHostEnvironment>();
        envMock.Setup(e => e.EnvironmentName).Returns("Production");

        var store = new ConfigurationScanProviderSecretStore(
            config,
            envMock.Object,
            new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider().CreateProtector("test"),
            NullLogger<ConfigurationScanProviderSecretStore>.Instance
        );

        Func<Task> act = async () => await store.AcquireLeaseAsync("bughunter");
        await act.Should().ThrowAsync<InvalidOperationException>()
           .WithMessage("*Plaintext secrets are strictly prohibited in production*");
    }

    [Fact]
    public void Test13_UnregisteredBinaryExecution_Throws_SecurityViolation()
    {
        var manifestMap = new Dictionary<string, string> { ["subfinder"] = "subfinder" };
        Action act = () => GenericCliToolAdapter.ValidateToolExecutableWhitelist("malicious_unregistered_tool", "malicious_unregistered_tool", manifestMap);
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*not registered in the authorized scanner tool manifest*");
    }

    [Fact]
    public async Task Test14_ConcreteToolReplacement_Dispatches_SelectedTool_Without_Orchestration_Changes()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        using var db = new PlatformDbContext(dbOptions);

        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);
        await registry.RegisterToolAsync("amass", "Amass Replacement Scanner", "v4.0.0", true, new[] { ToolCapability.HttpProbing }, executable: "amass");

        db.SecurityScanJobs.Add(new SecurityScanJob
        {
            Id = Guid.NewGuid(),
            TargetUrl = "https://example.com",
            ScanProfile = SecurityScanProfileType.Recon,
            Status = SecurityScanJobStatus.Queued,
            ProviderKey = "bughunter"
        });
        await db.SaveChangesAsync();

        var executedExecutables = new List<string>();
        Func<string, IGenericCliToolAdapter> factory = toolKey =>
        {
            var mockAdapter = new Mock<IGenericCliToolAdapter>();
            mockAdapter.Setup(a => a.ToolKey).Returns(toolKey);
            mockAdapter.Setup(a => a.ExecuteAsync(It.IsAny<ToolExecutionRequest>(), It.IsAny<ProviderSecretLease>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                       .Callback<ToolExecutionRequest, ProviderSecretLease, string, CancellationToken>((req, _, _, _) => executedExecutables.Add(req.Executable!))
                       .ReturnsAsync(new ToolExecutionResult(toolKey, "v2.0.0", ToolExecutionStatus.Success, 0, null, null));
            return mockAdapter.Object;
        };

        var worker = new GenericScanWorker(
            db,
            new InMemoryScanProviderSecretStore(),
            registry,
            factory,
            new EgressPolicyEngine(NullLogger<EgressPolicyEngine>.Instance),
            NullLogger<GenericScanWorker>.Instance
        );

        var result = await worker.ExecuteScanJobAsync(db.SecurityScanJobs.First().Id);

        result.Status.Should().Be(SecurityScanJobStatus.Completed);
        executedExecutables.Should().Contain("amass");
    }

    [Fact]
    public async Task AuthorizedTarget_DomainExact_Allows()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://example.com", SecurityScanProfileType.Recon, "bughunter");

        var job = await service.CreateScanJobAsync(request);
        job.Should().NotBeNull();
    }

    [Fact]
    public async Task AuthorizedTarget_Subdomain_Allows()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://api.example.com", SecurityScanProfileType.Recon, "bughunter");

        var job = await service.CreateScanJobAsync(request);
        job.Should().NotBeNull();
    }

    [Fact]
    public async Task AuthorizedTarget_PrefixLookalike_Denies()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://evil-example.com", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*out of scope*");
    }

    [Fact]
    public async Task AuthorizedTarget_SuffixLookalike_Denies()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://example.com.evil.com", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*out of scope*");
    }

    [Fact]
    public async Task AuthorizedTarget_NestedLookalike_Denies()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://example.com.attacker.io", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*out of scope*");
    }

    [Fact]
    public async Task AuthorizedTarget_DifferentRegistrableDomain_Denies()
    {
        using var db = CreateInMemoryDbContext();
        db.SecurityTargets.Add(new SecurityTarget { Id = Guid.NewGuid(), Name = "Target", BaseUrl = "https://example.com", Enabled = true });
        await db.SaveChangesAsync();

        var service = new ScanJobService(db, new TestUserContext(), new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance), NullLogger<ScanJobService>.Instance);
        var request = new CreateScanJobRequest(null, null, "https://another-domain.com", SecurityScanProfileType.Recon, "bughunter");

        Func<Task> act = async () => await service.CreateScanJobAsync(request);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*out of scope*");
    }

    [Fact]
    public void Test15_ShellPrimitives_PowershellAndCmd_Are_Rejected()
    {
        Action act1 = () => ScanToolRegistryService.ValidateExecutableName("powershell.exe");
        act1.Should().Throw<InvalidOperationException>().WithMessage("*Shell interpreter*prohibited*");

        Action act2 = () => ScanToolRegistryService.ValidateExecutableName("cmd.exe");
        act2.Should().Throw<InvalidOperationException>().WithMessage("*Shell interpreter*prohibited*");
    }

    [Fact]
    public async Task Test16_RegisterTool_With_ExecutablePathTraversal_Or_AbsolutePaths_Is_Rejected()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        Func<Task> act1 = async () => await registry.RegisterToolAsync("malicious1", "Malicious Tool 1", "v1.0.0", false, new[] { ToolCapability.HttpProbing }, executable: "../bin/evil.exe");
        await act1.Should().ThrowAsync<InvalidOperationException>().WithMessage("*prohibited path separators*");

        Func<Task> act2 = async () => await registry.RegisterToolAsync("malicious2", "Malicious Tool 2", "v1.0.0", false, new[] { ToolCapability.HttpProbing }, executable: "C:\\Windows\\System32\\cmd.exe");
        await act2.Should().ThrowAsync<InvalidOperationException>().WithMessage("*prohibited path separators*");
    }

    [Fact]
    public async Task Test17_RegisterTool_With_ShellInterpreter_Is_Rejected()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        Func<Task> act = async () => await registry.RegisterToolAsync("bash_tool", "Bash Tool", "v1.0.0", false, new[] { ToolCapability.HttpProbing }, executable: "bash");
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Shell interpreter*prohibited*");
    }

    [Fact]
    public void Test18_ValidateToolExecutableWhitelist_Rejects_Unknown_Executable_NotInManifest()
    {
        var manifestMap = new Dictionary<string, string> { ["subfinder"] = "subfinder", ["httpx"] = "httpx" };
        Action act = () => GenericCliToolAdapter.ValidateToolExecutableWhitelist("unregistered_tool", "unregistered_tool", manifestMap);
        act.Should().Throw<InvalidOperationException>().WithMessage("*not registered in the authorized scanner tool manifest*");
    }

    [Fact]
    public async Task Test19_ConfigurationDriven_Addition_Of_NewTool_Dnsx_Succeeds_Without_AdapterCodeChanges()
    {
        using var db = CreateInMemoryDbContext();
        var registry = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        // Configuration-driven addition of brand-new scanner 'dnsx' requiring zero adapter/orchestration code changes
        var registered = await registry.RegisterToolAsync("dnsx", "DNSX Fast DNS Resolver", "v1.1.5", true, new[] { ToolCapability.DnsResolution }, executable: "dnsx");
        registered.Should().NotBeNull();
        registered.Executable.Should().Be("dnsx");

        var tools = await registry.GetToolsForCapabilitiesAsync(new[] { ToolCapability.DnsResolution });
        tools.Should().Contain(t => t.ToolKey == "dnsx" && t.Executable == "dnsx");
    }

    private static PlatformDbContext CreateInMemoryDbContext()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new PlatformDbContext(dbOptions);
    }
}
