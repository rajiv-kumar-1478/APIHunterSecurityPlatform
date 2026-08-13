using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ToolDependencyValidatorTests
{
    private static PlatformDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new PlatformDbContext(options);
    }

    [Fact]
    public async Task ValidateDependencyGraphAsync_RejectsSelfDependency()
    {
        using var db = CreateDbContext();
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "bughunter", Executable = "bughunter", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "bughunter", DependencyToolKey = "bughunter", RequiredVersion = "1.0.0", RequiredSha256 = "abc" });
        await db.SaveChangesAsync();

        var validator = new ToolDependencyValidator(db, NullLogger<ToolDependencyValidator>.Instance);

        Func<Task> act = async () => await validator.ValidateDependencyGraphAsync("bughunter");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*self-dependency*");
    }

    [Fact]
    public async Task ValidateDependencyGraphAsync_RejectsCircularDependency()
    {
        using var db = CreateDbContext();
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "tool_a", Executable = "tool_a", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "tool_b", Executable = "tool_b", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "tool_c", Executable = "tool_c", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });

        // Cycle: A -> B -> C -> A
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "tool_a", DependencyToolKey = "tool_b", RequiredVersion = "1.0.0", RequiredSha256 = "abc" });
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "tool_b", DependencyToolKey = "tool_c", RequiredVersion = "1.0.0", RequiredSha256 = "abc" });
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "tool_c", DependencyToolKey = "tool_a", RequiredVersion = "1.0.0", RequiredSha256 = "abc" });
        await db.SaveChangesAsync();

        var validator = new ToolDependencyValidator(db, NullLogger<ToolDependencyValidator>.Instance);

        Func<Task> act = async () => await validator.ValidateDependencyGraphAsync("tool_a");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Cycle Detected*");
    }

    [Fact]
    public async Task ValidateDependencyGraphAsync_RejectsMissingDependency()
    {
        using var db = CreateDbContext();
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "bughunter", Executable = "bughunter", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "bughunter", DependencyToolKey = "missing_tool", RequiredVersion = "1.0.0", RequiredSha256 = "abc" });
        await db.SaveChangesAsync();

        var validator = new ToolDependencyValidator(db, NullLogger<ToolDependencyValidator>.Instance);

        Func<Task> act = async () => await validator.ValidateDependencyGraphAsync("bughunter");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*not registered*");
    }

    [Fact]
    public async Task ValidateDependencyGraphAsync_RejectsVersionMismatch()
    {
        using var db = CreateDbContext();
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "bughunter", Executable = "bughunter", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "subfinder", Executable = "subfinder", Version = "2.5.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "bughunter", DependencyToolKey = "subfinder", RequiredVersion = "2.6.6", RequiredSha256 = "abc" });
        await db.SaveChangesAsync();

        var validator = new ToolDependencyValidator(db, NullLogger<ToolDependencyValidator>.Instance);

        Func<Task> act = async () => await validator.ValidateDependencyGraphAsync("bughunter");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*requires 'subfinder' v2.6.6, but found v2.5.0*");
    }

    [Fact]
    public async Task ValidateDependencyGraphAsync_RejectsSha256Mismatch()
    {
        using var db = CreateDbContext();
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "bughunter", Executable = "bughunter", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "subfinder", Executable = "subfinder", Version = "2.6.6", ArtifactSha256 = "actual_sha256", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "bughunter", DependencyToolKey = "subfinder", RequiredVersion = "2.6.6", RequiredSha256 = "expected_sha256" });
        await db.SaveChangesAsync();

        var validator = new ToolDependencyValidator(db, NullLogger<ToolDependencyValidator>.Instance);

        Func<Task> act = async () => await validator.ValidateDependencyGraphAsync("bughunter");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*requires 'subfinder' SHA-256 'expected_sha256', but found 'actual_sha256'*");
    }

    [Fact]
    public async Task ValidateDependencyGraphAsync_SucceedsForValidDag()
    {
        using var db = CreateDbContext();
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "bughunter", Executable = "bughunter", Version = "1.0.0", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.SecurityScanTools.Add(new SecurityScanTool { ToolKey = "subfinder", Executable = "subfinder", Version = "2.6.6", ArtifactSha256 = "abc", HealthStatus = ToolHealthStatus.Healthy, Enabled = true });
        db.ToolDependencies.Add(new ToolDependency { ParentToolKey = "bughunter", DependencyToolKey = "subfinder", RequiredVersion = "2.6.6", RequiredSha256 = "abc" });
        await db.SaveChangesAsync();

        var validator = new ToolDependencyValidator(db, NullLogger<ToolDependencyValidator>.Instance);

        Func<Task> act = async () => await validator.ValidateDependencyGraphAsync("bughunter");
        await act.Should().NotThrowAsync();
    }
}
