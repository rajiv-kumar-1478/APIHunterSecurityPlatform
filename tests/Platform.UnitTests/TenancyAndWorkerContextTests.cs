using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Infrastructure.Tenancy;
using Platform.Infrastructure.Workers;
using Xunit;

namespace Platform.UnitTests;

public sealed class TenancyAndWorkerContextTests
{
    [Fact]
    public void ConfiguredTenantContext_UsesConfiguredTenantIdentity()
    {
        var tenantId = Guid.NewGuid();

        var context = new ConfiguredTenantContext(
            Options.Create(new TenantOptions { Id = tenantId }));

        context.TenantId.Should().Be(tenantId);
    }

    [Fact]
    public void ConfiguredTenantContext_RejectsEmptyTenantIdentity()
    {
        var act = () => new ConfiguredTenantContext(
            Options.Create(new TenantOptions { Id = Guid.Empty }));

        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*Tenant:Id*");
    }

    [Fact]
    public void WorkerUserContext_IsAnonymousAndNeverPlatformAdmin()
    {
        var context = new WorkerUserContext();

        context.UserId.Should().BeNull();
        context.SessionId.Should().BeNull();
        context.IsAuthenticated.Should().BeFalse();
        context.IsPlatformAdmin.Should().BeFalse();
        context.IpAddress.Should().Be("127.0.0.1");
        context.CorrelationId.Should().HaveLength(32);
        context.CorrelationId.Should().Be(context.CorrelationId);
    }

    [Fact]
    public async Task DisabledSecurityScanJobConsumer_AcceptsConfiguredTenantWithoutCreatingScope()
    {
        var scopeFactory = new Mock<IServiceScopeFactory>(MockBehavior.Strict);
        var worker = new SecurityScanJobConsumerWorker(
            scopeFactory.Object,
            Options.Create(new ScanJobConsumerOptions { Enabled = false }),
            new TestTenantContext(),
            NullLogger<SecurityScanJobConsumerWorker>.Instance);

        await worker.StartAsync(CancellationToken.None);
        await worker.StopAsync(CancellationToken.None);

        scopeFactory.VerifyNoOtherCalls();
    }
}
