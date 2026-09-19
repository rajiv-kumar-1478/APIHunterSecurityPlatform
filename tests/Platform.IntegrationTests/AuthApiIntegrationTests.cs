using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Platform.Api.Controllers;
using Platform.Domain.Entities;
using Platform.Infrastructure.Persistence;

namespace Platform.IntegrationTests;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName = $"AuthIntegration-{Guid.NewGuid():N}";

    protected virtual int LoginMaxAttempts => 1000;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Tenant:Id", TestTenantContext.DefaultTenantId.ToString());
        builder.UseSetting("Seed:AdminEmail", "admin@localhost");
        builder.UseSetting("Seed:AdminPassword", "ChangeMe123!");
        builder.UseSetting("RateLimiting:LoginMaxAttempts", LoginMaxAttempts.ToString());
        builder.UseSetting("RateLimiting:LoginWindowSeconds", "300");

        builder.ConfigureServices(services =>
        {
            var dbContextDescriptor = services.SingleOrDefault(
                descriptor => descriptor.ServiceType == typeof(DbContextOptions<PlatformDbContext>));
            if (dbContextDescriptor != null)
            {
                services.Remove(dbContextDescriptor);
            }

            services.AddDbContext<PlatformDbContext>(options =>
            {
                options.UseInMemoryDatabase(_databaseName);
            });
        });
    }
}

public sealed class RateLimitedWebApplicationFactory : CustomWebApplicationFactory
{
    protected override int LoginMaxAttempts => 2;
}

[CollectionDefinition("Auth API integration", DisableParallelization = true)]
public sealed class AuthApiIntegrationCollection;

[Collection("Auth API integration")]
public class AuthApiIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private const string TestPassword = "ValidPassword123!";
    private readonly CustomWebApplicationFactory _factory;

    public AuthApiIntegrationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task GetHealth_ReturnsAlivePayload()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/v1/health");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await response.Content.ReadFromJsonAsync<HealthPayload>();
        payload.Should().NotBeNull();
        payload!.Status.Should().Be("Alive");
    }

    [Fact]
    public async Task ProtectedEndpoint_WithoutAuthentication_Returns401Unauthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/v1/users");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task FallbackPolicy_ProtectsControllerWithoutExplicitAuthorizeAttribute()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/v1/findings?page=1&pageSize=1");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AdminEndpoint_WithoutAuthentication_Returns401Unauthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/permissions");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task PlatformAdminPolicy_WithAuthenticatedNonAdmin_Returns403Forbidden()
    {
        var user = await SeedUserAsync(isPlatformAdmin: false);
        var client = CreateCookieClient();
        using var loginResponse = await LoginAsync(client, user.Email, TestPassword);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var response = await client.GetAsync("/api/v1/users");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task CsrfBootstrap_AllowsAnonymousCallerAndSetsCookie()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/v1/auth/csrf");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await response.Content.ReadFromJsonAsync<CsrfPayload>();
        payload!.CsrfToken.Should().NotBeNullOrWhiteSpace();
        response.Headers.TryGetValues("Set-Cookie", out var cookies).Should().BeTrue();
        cookies!.Should().Contain(cookie => cookie.Contains("__ap_csrf=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Login_WithCsrfCookieAndHeader_ReturnsRealUserId_AndMeUsesSameIdentity()
    {
        var client = CreateCookieClient();

        using var response = await LoginAsync(client, "admin@localhost", "ChangeMe123!");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var login = await response.Content.ReadFromJsonAsync<LoginPayload>();
        login.Should().NotBeNull();
        login!.CsrfToken.Should().NotBeNullOrWhiteSpace();
        login.IsPlatformAdmin.Should().BeTrue();

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var persistedUserId = await db.Users
            .Where(user => user.Email == "admin@localhost")
            .Select(user => user.Id)
            .SingleAsync();
        login.UserId.Should().Be(persistedUserId);

        var meResponse = await client.GetAsync("/api/v1/auth/me");
        meResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var me = await meResponse.Content.ReadFromJsonAsync<MePayload>();
        Guid.Parse(me!.UserId).Should().Be(persistedUserId);
        me.IsPlatformAdmin.Should().BeTrue();
    }

    [Fact]
    public async Task Login_WithInvalidPasswordAndValidCsrf_Returns401Unauthorized()
    {
        var client = CreateCookieClient();

        using var response = await LoginAsync(client, "admin@localhost", "WrongPassword!");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("Invalid credentials");
    }

    [Fact]
    public async Task AuthenticatedMutation_WithoutCsrfHeader_Returns400BadRequest()
    {
        var client = CreateCookieClient();
        using var loginResponse = await LoginAsync(client, "admin@localhost", "ChangeMe123!");
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var response = await client.PostAsJsonAsync("/api/v1/auth/logout", new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadFromJsonAsync<ErrorPayload>();
        body!.Code.Should().Be("INVALID_CSRF_TOKEN");
    }

    [Fact]
    public async Task CurrentUser_CanListAndRevokeOwnSession_ThenCookieIsRejected()
    {
        var user = await SeedUserAsync(isPlatformAdmin: false);
        var client = CreateCookieClient();
        using var loginResponse = await LoginAsync(client, user.Email, TestPassword);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var login = await loginResponse.Content.ReadFromJsonAsync<LoginPayload>();

        var sessionsResponse = await client.GetAsync("/api/v1/auth/sessions");
        sessionsResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var sessions = await sessionsResponse.Content.ReadFromJsonAsync<List<SessionPayload>>();
        sessions.Should().ContainSingle(session => session.IsCurrent);

        var revokeRequest = new HttpRequestMessage(
            HttpMethod.Delete,
            $"/api/v1/auth/sessions/{sessions!.Single(session => session.IsCurrent).Id}");
        revokeRequest.Headers.TryAddWithoutValidation("X-CSRF-TOKEN", login!.CsrfToken);
        var revokeResponse = await client.SendAsync(revokeRequest);
        revokeResponse.StatusCode.Should().Be(HttpStatusCode.NoContent);

        var meResponse = await client.GetAsync("/api/v1/auth/me");
        meResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    [InlineData("disabled")]
    [InlineData("admin-demoted")]
    public async Task CookieValidation_RejectsInvalidDatabaseBackedSessionState(string invalidState)
    {
        var user = await SeedUserAsync(isPlatformAdmin: invalidState == "admin-demoted");
        var client = CreateCookieClient();
        using var loginResponse = await LoginAsync(client, user.Email, TestPassword);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var persistedUser = await db.Users.SingleAsync(candidate => candidate.Id == user.Id);
            var session = await db.AuthenticationSessions
                .Where(candidate => candidate.UserId == user.Id)
                .OrderByDescending(candidate => candidate.CreatedAtUtc)
                .FirstAsync();

            switch (invalidState)
            {
                case "revoked":
                    session.RevokedAtUtc = DateTime.UtcNow;
                    break;
                case "expired":
                    session.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
                    break;
                case "disabled":
                    persistedUser.IsActive = false;
                    break;
                case "admin-demoted":
                    persistedUser.IsPlatformAdmin = false;
                    break;
                default:
                    throw new InvalidOperationException($"Unknown invalid state '{invalidState}'.");
            }

            await db.SaveChangesAsync();
        }

        var response = await client.GetAsync("/api/v1/auth/me");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private HttpClient CreateCookieClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = true
    });

    private async Task<User> SeedUserAsync(bool isPlatformAdmin)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<User>>();
        var id = Guid.NewGuid();
        var user = new User
        {
            Id = id,
            Email = $"auth-{id:N}@test.local",
            Username = $"auth-{id:N}",
            DisplayName = "Authentication Test User",
            IsActive = true,
            IsPlatformAdmin = isPlatformAdmin
        };
        user.PasswordHash = passwordHasher.HashPassword(user, TestPassword);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    internal static async Task<HttpResponseMessage> LoginAsync(
        HttpClient client,
        string email,
        string password)
    {
        var csrfResponse = await client.GetAsync("/api/v1/auth/csrf");
        csrfResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var csrf = await csrfResponse.Content.ReadFromJsonAsync<CsrfPayload>();
        csrf!.CsrfToken.Should().NotBeNullOrWhiteSpace();

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login")
        {
            Content = JsonContent.Create(new LoginRequest(email, password, false))
        };
        request.Headers.TryAddWithoutValidation("X-CSRF-TOKEN", csrf.CsrfToken);
        return await client.SendAsync(request);
    }

    private sealed record HealthPayload(string Status, DateTime Timestamp);
    internal sealed record CsrfPayload(string CsrfToken);
    private sealed record LoginPayload(Guid UserId, bool IsPlatformAdmin, DateTime ExpiresAt, string CsrfToken);
    private sealed record MePayload(string UserId, bool IsPlatformAdmin);
    private sealed record SessionPayload(Guid Id, bool IsCurrent);
    private sealed record ErrorPayload(string Code);
}

[Collection("Auth API integration")]
public class LoginRateLimitIntegrationTests : IClassFixture<RateLimitedWebApplicationFactory>
{
    private readonly RateLimitedWebApplicationFactory _factory;

    public LoginRateLimitIntegrationTests(RateLimitedWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task LoginPolicy_RejectsRequestsBeyondConfiguredWindowLimit()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        using var first = await AuthApiIntegrationTests.LoginAsync(client, "unknown-1@test.local", "invalid");
        using var second = await AuthApiIntegrationTests.LoginAsync(client, "unknown-2@test.local", "invalid");
        using var rejected = await AuthApiIntegrationTests.LoginAsync(client, "unknown-3@test.local", "invalid");

        first.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        second.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        rejected.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }
}
