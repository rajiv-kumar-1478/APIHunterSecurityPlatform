using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Platform.Api.Middleware;
using Platform.Api.Services;
using Xunit;

namespace Platform.UnitTests.Hardening;

public class RateLimitingAndSecurityHeadersTests
{
    [Fact]
    public async Task SecurityHeadersMiddleware_InjectsExpectedHardeningHeaders()
    {
        var context = new DefaultHttpContext();
        context.Request.IsHttps = true;

        var middleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context);

        context.Response.Headers.XContentTypeOptions.ToString().Should().Be("nosniff");
        context.Response.Headers.XFrameOptions.ToString().Should().Be("DENY");
        context.Response.Headers["Referrer-Policy"].ToString().Should().Be("strict-origin-when-cross-origin");
        context.Response.Headers.StrictTransportSecurity.ToString().Should().Contain("max-age=31536000");
        context.Response.Headers["Content-Security-Policy"].ToString().Should().Contain("default-src 'self'");
    }

    [Fact]
    public async Task EnvironmentValidationService_ThrowsInProduction_WhenMasterKeyIsWeak()
    {
        var inMemorySettings = new Dictionary<string, string?>
        {
            { "Database:ConnectionString", "Host=localhost;Database=test;Username=postgres;Password=postgres" },
            { "Security:MasterEncryptionKey", "short_key_16_bytes" } // < 32 bytes
        };

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        var mockEnv = new Mock<IHostEnvironment>();
        mockEnv.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var service = new EnvironmentValidationHostedService(config, mockEnv.Object, NullLogger<EnvironmentValidationHostedService>.Instance);

        var act = async () => await service.StartAsync(CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*insufficient entropy*");
    }

    [Fact]
    public async Task EnvironmentValidationService_PassesInProduction_WhenKeysMeetEntropyRequirement()
    {
        var inMemorySettings = new Dictionary<string, string?>
        {
            { "Database:ConnectionString", "Host=localhost;Database=test;Username=postgres;Password=postgres" },
            { "Security:MasterEncryptionKey", "01234567890123456789012345678901_32_bytes_ok" },
            { "Authentication:JwtSecret", "01234567890123456789012345678901_32_bytes_ok" }
        };

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        var mockEnv = new Mock<IHostEnvironment>();
        mockEnv.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var service = new EnvironmentValidationHostedService(config, mockEnv.Object, NullLogger<EnvironmentValidationHostedService>.Instance);

        var act = async () => await service.StartAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
    }
}
