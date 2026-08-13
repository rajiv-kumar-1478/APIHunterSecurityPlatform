using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class ScanToolRegistryServiceTests
{
    private PlatformDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new PlatformDbContext(options);
    }

    [Fact]
    public async Task Test1_RegisterTool_Succeeds_ForValidTool()
    {
        var db = CreateDbContext();
        var service = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        var tool = await service.RegisterToolAsync("subfinder", "Subfinder", "v2.14.0", true, new[] { ToolCapability.SubdomainEnumeration }, executable: "subfinder");

        tool.Should().NotBeNull();
        tool.ToolKey.Should().Be("subfinder");
        tool.Version.Should().Be("v2.14.0");

        var dbTool = await db.SecurityScanTools.FirstOrDefaultAsync(t => t.ToolKey == "subfinder");
        dbTool.Should().NotBeNull();
    }

    [Fact]
    public async Task RegisterTool_Throws_WhenExecutableEmpty()
    {
        var db = CreateDbContext();
        var service = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        var act = async () => await service.RegisterToolAsync("subfinder", "Subfinder", "v2.14.0", true, new[] { ToolCapability.SubdomainEnumeration }, executable: "");
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*cannot be empty*");
    }

    [Fact]
    public async Task Test2_RegisterTool_Throws_OnDuplicateToolKey()
    {
        var db = CreateDbContext();
        var service = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        await service.RegisterToolAsync("httpx", "HTTPX", "v1.6.0", true, new[] { ToolCapability.HttpProbing }, executable: "httpx");

        var act = async () => await service.RegisterToolAsync("httpx", "HTTPX Duplicate", "v1.6.0", true, new[] { ToolCapability.HttpProbing }, executable: "httpx");
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*already registered*");
    }

    [Fact]
    public async Task Test3_GetToolsForCapabilities_ReturnsMatchingTools()
    {
        var db = CreateDbContext();
        var service = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        await service.RegisterToolAsync("subfinder", "Subfinder", "v2.14.0", true, new[] { ToolCapability.SubdomainEnumeration }, executable: "subfinder");
        await service.RegisterToolAsync("httpx", "HTTPX", "v1.6.0", true, new[] { ToolCapability.HttpProbing }, executable: "httpx");

        var tools = await service.GetToolsForCapabilitiesAsync(new[] { ToolCapability.HttpProbing });
        tools.Should().HaveCount(1);
        tools.First().ToolKey.Should().Be("httpx");
    }

    [Fact]
    public async Task Test4_GetCapabilityManifest_ReturnsAllSupportedCapabilities()
    {
        var db = CreateDbContext();
        var service = new ScanToolRegistryService(db, NullLogger<ScanToolRegistryService>.Instance);

        await service.RegisterToolAsync("subfinder", "Subfinder", "v2.14.0", true, new[] { ToolCapability.SubdomainEnumeration }, executable: "subfinder");

        var manifest = await service.GetCapabilityManifestAsync();
        manifest.Should().NotBeEmpty();
        manifest.Should().Contain(c => c.CapabilityKey == "SubdomainEnumeration" && c.AvailableTools.Contains("subfinder"));
    }
}
