using System.IO;
using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Platform.IntegrationTests;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            var dbContextDescriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<Platform.Infrastructure.Persistence.PlatformDbContext>));
            if (dbContextDescriptor != null) services.Remove(dbContextDescriptor);

            services.AddDbContext<Platform.Infrastructure.Persistence.PlatformDbContext>(options =>
            {
                options.UseInMemoryDatabase($"TestDb_{Guid.NewGuid()}");
            });
        });

        return base.CreateHost(builder);
    }
}

public class AuthApiIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;

    public AuthApiIntegrationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task GetHealth_Returns200OK()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/api/v1/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("Healthy");
    }

    [Fact]
    public async Task ProtectedEndpoint_WithoutAuthentication_Returns401Unauthorized()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/api/v1/users");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("UNAUTHENTICATED");
    }

    [Fact]
    public async Task AdminEndpoint_WhenNotAdmin_Returns401Unauthorized()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/api/v1/admin/permissions");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
