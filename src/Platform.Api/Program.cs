using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Platform.Api.Middleware;
using Platform.Application.Auth;
using Platform.Application.Audit;
using Platform.Application.Configuration;
using Platform.Application.Health;
using Platform.Application.Notifications;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Users;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Infrastructure.Authentication;
using Platform.Infrastructure.Health;
using Platform.Infrastructure.Notifications;
using Platform.Infrastructure.Persistence;
using Serilog;
using Serilog.Events;

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap Serilog early so startup errors are captured
// ─────────────────────────────────────────────────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [{CorrelationId}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/platform-.txt", rollingInterval: RollingInterval.Day)
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting APIHunter Security Intelligence Platform");

    var builder = WebApplication.CreateBuilder(args);
    builder.Host.UseSerilog((ctx, services, config) => config
        .ReadFrom.Configuration(ctx.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .MinimumLevel.Override("Microsoft.EntityFrameworkCore.Database.Command", LogEventLevel.Warning)
        .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [{CorrelationId}] {Message:lj}{NewLine}{Exception}")
        .WriteTo.File("logs/platform-.txt", rollingInterval: RollingInterval.Day));

    // ─────────────────────────────────────────────────────────────────────────
    // Configuration Binding (strongly typed — no direct env var access below)
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.Configure<AuthenticationOptions>(builder.Configuration.GetSection(AuthenticationOptions.SectionName));
    builder.Services.Configure<DatabaseOptions>(builder.Configuration.GetSection(DatabaseOptions.SectionName));
    builder.Services.Configure<CorsOptions>(builder.Configuration.GetSection(CorsOptions.SectionName));
    builder.Services.Configure<Platform.Application.Configuration.DataProtectionOptions>(builder.Configuration.GetSection(Platform.Application.Configuration.DataProtectionOptions.SectionName));
    builder.Services.Configure<RateLimitingOptions>(builder.Configuration.GetSection(RateLimitingOptions.SectionName));
    builder.Services.Configure<NotificationOptions>(builder.Configuration.GetSection(NotificationOptions.SectionName));
    builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection(SmtpOptions.SectionName));
    builder.Services.Configure<SendGridOptions>(builder.Configuration.GetSection(SendGridOptions.SectionName));
    builder.Services.Configure<MailgunOptions>(builder.Configuration.GetSection(MailgunOptions.SectionName));
    builder.Services.Configure<SeedOptions>(builder.Configuration.GetSection(SeedOptions.SectionName));

    // ─────────────────────────────────────────────────────────────────────────
    // Database
    // ─────────────────────────────────────────────────────────────────────────
    var connStr = builder.Configuration["Database:ConnectionString"]
               ?? builder.Configuration.GetConnectionString("Default");

    builder.Services.AddDbContext<PlatformDbContext>(opts =>
    {
        if (builder.Environment.IsEnvironment("Testing") || string.IsNullOrWhiteSpace(connStr) || connStr.Equals("InMemory", StringComparison.OrdinalIgnoreCase))
        {
            opts.UseInMemoryDatabase("PlatformTestDb");
        }
        else
        {
            opts.UseNpgsql(connStr, npg =>
                npg.MigrationsAssembly(typeof(PlatformDbContext).Assembly.FullName));
        }
    });

    builder.Services.AddScoped<IPlatformDbContext>(sp => sp.GetRequiredService<PlatformDbContext>());
    builder.Services.AddScoped<DatabaseSeeder>();

    // ─────────────────────────────────────────────────────────────────────────
    // Data Protection (ASP.NET Core — persistent keys)
    // ─────────────────────────────────────────────────────────────────────────
    var dpBuilder = builder.Services.AddDataProtection()
        .SetApplicationName(builder.Configuration["DataProtection:ApplicationName"] ?? "APIHunterPlatform");

    var dpKeyPath = builder.Configuration["DataProtection:KeyPath"];
    if (!string.IsNullOrWhiteSpace(dpKeyPath))
        dpBuilder.PersistKeysToFileSystem(new DirectoryInfo(dpKeyPath));

    // ─────────────────────────────────────────────────────────────────────────
    // Authentication + CSRF
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddAuthentication("Platform")
        .AddCookie("Platform", opts =>
        {
            opts.Cookie.Name = "__ap_session";
            opts.Cookie.HttpOnly = true;
            opts.Cookie.SameSite = SameSiteMode.Lax;
            opts.Cookie.SecurePolicy = builder.Environment.IsProduction()
                ? CookieSecurePolicy.Always
                : CookieSecurePolicy.SameAsRequest;

            // Return 401 JSON for API endpoints — no redirect
            opts.Events.OnRedirectToLogin = ctx =>
            {
                ctx.Response.StatusCode = 401;
                return Task.CompletedTask;
            };
            opts.Events.OnRedirectToAccessDenied = ctx =>
            {
                ctx.Response.StatusCode = 403;
                return Task.CompletedTask;
            };
        });

    builder.Services.AddAntiforgery(opts =>
    {
        opts.HeaderName = "X-CSRF-TOKEN";
        opts.Cookie.Name = "__ap_csrf";
        opts.Cookie.SameSite = SameSiteMode.Strict;
        opts.Cookie.HttpOnly = true;
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Rate Limiting (IP + Account lockout is in AuthService)
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddRateLimiter(opts =>
    {
        opts.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "anon",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = int.Parse(builder.Configuration["RateLimiting:LoginMaxAttempts"] ?? "5"),
                Window = TimeSpan.FromSeconds(int.Parse(builder.Configuration["RateLimiting:LoginWindowSeconds"] ?? "300"))
            }));

        opts.RejectionStatusCode = 429;
    });

    // ─────────────────────────────────────────────────────────────────────────
    // CORS
    // ─────────────────────────────────────────────────────────────────────────
    var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                      ?? ["http://localhost:3000"];

    builder.Services.AddCors(opts => opts.AddDefaultPolicy(policy =>
        policy.WithOrigins(allowedOrigins)
              .AllowCredentials()
              .AllowAnyHeader()
              .AllowAnyMethod()));

    // ─────────────────────────────────────────────────────────────────────────
    // Application Services
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
    builder.Services.AddScoped<AuthService>();
    builder.Services.AddScoped<UserService>();
    builder.Services.AddScoped<PermissionService>();
    builder.Services.AddScoped<IAuditService, AuditService>();
    builder.Services.AddScoped<AuditQueryService>();
    builder.Services.AddScoped<HealthAggregatorService>();
    builder.Services.AddScoped<INotificationService, NotificationService>();
    builder.Services.AddScoped<IProviderSelector, ProviderSelector>();

    // ─────────────────────────────────────────────────────────────────────────
    // Notification Providers (all registered; ProviderSelector picks active one)
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddScoped<INotificationProvider, SmtpNotificationProvider>();
    builder.Services.AddScoped<INotificationProvider, SendGridNotificationProvider>();
    builder.Services.AddScoped<INotificationProvider, MailgunNotificationProvider>();
    builder.Services.AddHttpClient("Mailgun");

    // ─────────────────────────────────────────────────────────────────────────
    // Health Components
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddScoped<IHealthComponent, PostgresHealthComponent>();
    builder.Services.AddScoped<IHealthComponent, ApiHealthComponent>();

    // ─────────────────────────────────────────────────────────────────────────
    // Current User Context
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();
    builder.Services.AddScoped<ICurrentUserContextProvider>(sp =>
        (HttpCurrentUserContext)sp.GetRequiredService<ICurrentUserContext>());

    // ─────────────────────────────────────────────────────────────────────────
    // OpenTelemetry
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService("APIHunterPlatform"))
        .WithTracing(t => t.AddAspNetCoreInstrumentation())
        .WithMetrics(m => m.AddAspNetCoreInstrumentation());

    // ─────────────────────────────────────────────────────────────────────────
    // Controllers + OpenAPI
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(opts =>
    {
        opts.SwaggerDoc("v1", new() { Title = "APIHunter Security Platform API", Version = "v1" });
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Build
    // ─────────────────────────────────────────────────────────────────────────
    var app = builder.Build();

    // Run migrations and seed on startup
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        if (db.Database.IsRelational())
            await db.Database.MigrateAsync();
        else
            await db.Database.EnsureCreatedAsync();

        var seeder = scope.ServiceProvider.GetRequiredService<DatabaseSeeder>();
        await seeder.SeedAsync();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Middleware Pipeline
    // ─────────────────────────────────────────────────────────────────────────
    app.UseMiddleware<ErrorHandlingMiddleware>();
    app.UseMiddleware<CorrelationIdMiddleware>();
    app.UseSerilogRequestLogging();
    app.UseCors();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI(opts =>
        {
            opts.SwaggerEndpoint("/swagger/v1/swagger.json", "Platform API v1");
            opts.RoutePrefix = "swagger";
        });
    }

    app.UseAuthentication();
    app.UseAuthorization();
    app.UseRateLimiter();
    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application startup failed");
}
finally
{
    Log.CloseAndFlush();
}

public partial class Program { }
