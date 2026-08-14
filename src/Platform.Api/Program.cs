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
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Infrastructure.Scanning;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Providers;
using Platform.Application.Services;
using Platform.Application.Verification;
using Platform.Domain.Enums;
using Platform.Infrastructure.Remediation;
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
    builder.Services.Configure<ApiHunterSourceOptions>(builder.Configuration.GetSection(ApiHunterSourceOptions.SectionName));
    builder.Services.Configure<GitHubOptions>(builder.Configuration.GetSection(GitHubOptions.SectionName));
    builder.Services.Configure<ObjectStoreOptions>(builder.Configuration.GetSection(ObjectStoreOptions.SectionName));
    builder.Services.Configure<DetectionOptions>(builder.Configuration.GetSection(DetectionOptions.SectionName));
    builder.Services.Configure<AiRouterOptions>(builder.Configuration.GetSection(AiRouterOptions.SectionName));


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
    builder.Services.AddSingleton<IApiHunterStatusMapper, Platform.Infrastructure.Adapters.ApiHunter.ApiHunterStatusMapper>();
    builder.Services.AddScoped<IApiHunterSource, Platform.Infrastructure.Adapters.ApiHunter.ApiHunterAdapter>();
    builder.Services.AddScoped<ApiHunterSyncService>();

    // Phase 3 Application Services
    builder.Services.AddScoped<RepositoryAcquisitionService>();
    builder.Services.AddScoped<SnapshotService>();
    builder.Services.AddScoped<SecretDetectionService>();
    builder.Services.AddScoped<CandidateService>();
    builder.Services.AddScoped<JobOrchestrationService>();

    // Phase 4 Application Services & Adapters
    builder.Services.AddHttpClient("AiProviderHttpClient");
    builder.Services.AddScoped<IAiModelRouter, Platform.Infrastructure.Adapters.AI.AiModelRouter>();
    builder.Services.AddScoped<AiProviderRegistryService>();
    builder.Services.AddScoped<Platform.Infrastructure.Services.AiInvestigationEngine>();
    builder.Services.AddScoped<AiInvestigationService>();
    builder.Services.AddScoped<Platform.Application.Services.SecurityIntelligenceGraphBuilder>();
    builder.Services.AddScoped<SecurityIntelligenceService>();

    // Phase 5 Application Services & Validation Plugins
    builder.Services.Configure<ValidationPolicyOptions>(builder.Configuration.GetSection(ValidationPolicyOptions.SectionName));
    builder.Services.AddSingleton<Platform.Infrastructure.Security.ValidationEndpointRegistry>();
    builder.Services.AddSingleton<Platform.Infrastructure.Security.SsrfProtectionService>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.OpenAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.AnthropicCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.DeepSeekCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.GroqCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.AwsStsCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.GitHubCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.StripeCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.SendGridCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.MailgunCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.SlackCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.FallbackCredentialValidator>();
    builder.Services.AddScoped<CredentialValidationService>();

    // Phase 6 Application Services
    var riskPolicy = new RiskPolicyOptions();
    builder.Configuration.GetSection(RiskPolicyOptions.SectionName).Bind(riskPolicy);
    builder.Services.AddSingleton(riskPolicy);
    builder.Services.AddSingleton<RiskEngine>();
    builder.Services.AddScoped<SecurityFindingService>();
    builder.Services.AddScoped<GraphIntelligenceEngine>();
    builder.Services.AddScoped<ExposureAnalysisService>();
    builder.Services.AddScoped<SecurityFindingLifecycleService>();

    // Phase 6 Step 6 — Continuous Revalidation
    builder.Services.Configure<ContinuousRevalidationOptions>(
        builder.Configuration.GetSection(ContinuousRevalidationOptions.SectionName));
    builder.Services.AddScoped<ValidationStateChangeProcessor>();
    builder.Services.AddHostedService<Platform.Infrastructure.Workers.ContinuousRevalidationWorker>();

    // Phase 6 Step 7 — Security Alerting & High-Fidelity Notifications
    builder.Services.Configure<SecurityAlertOptions>(
        builder.Configuration.GetSection(SecurityAlertOptions.SectionName));
    builder.Services.AddScoped<SecurityAlertService>();

    // Phase 7 Step 1, 2 & 3 — Remediation Action Domain, Recommendation & Response Policy Engine
    var recPolicy = new RemediationRecommendationPolicyOptions();
    builder.Configuration.GetSection(RemediationRecommendationPolicyOptions.SectionName).Bind(recPolicy);
    builder.Services.AddSingleton(recPolicy);
    builder.Services.AddSingleton<RemediationRecommendationEngine>();

    var respPolicy = new ResponsePolicyOptions();
    builder.Configuration.GetSection(ResponsePolicyOptions.SectionName).Bind(respPolicy);
    builder.Services.AddSingleton(respPolicy);
    builder.Services.AddSingleton<ResponsePolicyEngine>();

    builder.Services.AddScoped<RemediationActionService>();
    builder.Services.AddScoped<RemediationApprovalService>();

    // Phase 7 Step 5 — Remediation Execution Engine & Providers
    builder.Services.AddSingleton<IProtectedCredentialResolver, SafeProtectedCredentialResolver>();
    builder.Services.AddSingleton<IRemediationProvider, GitHubRemediationProvider>();
    builder.Services.AddSingleton<IRemediationProvider, SafeFallbackRemediationProvider>();
    builder.Services.AddScoped<RemediationExecutionService>();

    // Phase 7 Step 6 — Post-Remediation Verification Engine & Strategies
    builder.Services.AddSingleton<IVerificationStrategy, RevokeCredentialVerificationStrategy>();
    builder.Services.AddSingleton<IVerificationStrategy, FallbackVerificationStrategy>();
    builder.Services.AddScoped<PostRemediationVerificationService>();

    // Phase 8 — Hosted Security Scanning & Scan Foundation
    builder.Services.AddScoped<ScanToolRegistryService>();
    builder.Services.AddScoped<ScanJobService>();
    builder.Services.AddScoped<ScanPostExecutionProcessor>();
    builder.Services.AddScoped<IScanToolHealthService, ScanToolHealthService>();
    builder.Services.AddSingleton<IBugHunterProvider, BugHunterScanProvider>();
    builder.Services.AddSingleton<IScanProvider, BugHunterScanProvider>();
    builder.Services.AddTransient<Func<string, IGenericCliToolAdapter>>(sp => toolKey =>
        new GenericCliToolAdapter(toolKey, sp.GetRequiredService<ILogger<GenericCliToolAdapter>>()));
    builder.Services.AddScoped<IScanWorker, GenericScanWorker>();

    var scannerOptions = builder.Configuration.GetSection("ScannerRuntime").Get<ScannerRuntimeOptions>() ?? new ScannerRuntimeOptions();
    builder.Services.AddSingleton(scannerOptions);
    builder.Services.AddSingleton<IEgressPolicyEngine, EgressPolicyEngine>();
    builder.Services.AddSingleton<EnforcedEgressGateway>();
    builder.Services.AddSingleton<IEnforcedEgressGateway>(sp => sp.GetRequiredService<EnforcedEgressGateway>());
    builder.Services.AddSingleton<IEgressNetworkProxy>(sp => sp.GetRequiredService<EnforcedEgressGateway>());
    builder.Services.AddSingleton<IScannerRuntimeSandbox>(sp =>
    {
        var options = sp.GetRequiredService<ScannerRuntimeOptions>();
        var egressGateway = sp.GetRequiredService<IEnforcedEgressGateway>();
        var cliAdapterFactory = sp.GetRequiredService<Func<string, IGenericCliToolAdapter>>();

        if (options.RuntimeMode == ScannerRuntimeMode.CloudManagedContainer)
        {
            var httpClient = new HttpClient
            {
                BaseAddress = !string.IsNullOrWhiteSpace(options.HostedScannerServiceEndpoint)
                    ? new Uri(options.HostedScannerServiceEndpoint.TrimEnd('/') + "/")
                    : null,
                Timeout = options.ExecutionTimeout
            };

            return new HostedScannerRuntime(
                httpClient,
                options.HostedScannerServiceKey,
                egressGateway,
                sp.GetRequiredService<ILogger<HostedScannerRuntime>>());
        }

        return new DockerScannerRuntime(
            options,
            cliAdapterFactory,
            egressGateway,
            sp.GetRequiredService<ILogger<DockerScannerRuntime>>());
    });

    if (builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("Testing"))
    {
        builder.Services.AddSingleton<IScanProviderSecretStore, InMemoryScanProviderSecretStore>();
    }
    else
    {
        builder.Services.AddSingleton<IScanProviderSecretStore, ConfigurationScanProviderSecretStore>();
    }








    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3 Infrastructure Adapters
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddScoped<IGitHubCredentialProvider, Platform.Infrastructure.Adapters.GitHub.GitHubAppCredentialProvider>();
    builder.Services.AddScoped<IGitHubCredentialProvider, Platform.Infrastructure.Adapters.GitHub.GitHubPatCredentialProvider>();
    builder.Services.AddScoped<IRepositoryProvider, Platform.Infrastructure.Adapters.GitHub.GitHubRepositoryProvider>();
    builder.Services.AddHttpClient("GitHubArchive");

    if (builder.Environment.IsDevelopment())
    {
        builder.Services.AddScoped<IObjectStore, Platform.Infrastructure.Adapters.ObjectStore.FileSystemObjectStore>();
    }
    else
    {
        builder.Services.AddScoped<IObjectStore, Platform.Infrastructure.Adapters.ObjectStore.S3ObjectStoreAdapter>();
    }

    builder.Services.AddScoped<ISecretDetector, Platform.Infrastructure.Adapters.Detection.RegexSecretDetector>();

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
    builder.Services.AddScoped<IHealthComponent, Platform.Infrastructure.Health.ApiHunterHealthComponent>();


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
    builder.Services.AddControllersWithViews();
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
