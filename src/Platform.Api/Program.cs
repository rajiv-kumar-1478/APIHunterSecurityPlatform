using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.HttpOverrides;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Platform.Api.Configuration;
using Platform.Api.Filters;
using Platform.Api.Middleware;
using Platform.Application.Auth;
using Platform.Application.Audit;
using Platform.Application.Configuration;
using Platform.Application.Health;
using Platform.Application.Notifications;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Reporting.Formatters;
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
using Platform.Infrastructure.Tenancy;
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
    // Production Security Configuration Validation (Fail-Closed Startup Guard)
    // ─────────────────────────────────────────────────────────────────────────
    if (builder.Environment.IsProduction())
    {
        ProductionSecurityConfigurationValidator.Validate(builder.Configuration, requireHttps: false);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Configuration Binding (strongly typed — no direct env var access below)
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services
        .AddOptions<Platform.Application.Configuration.AuthenticationOptions>()
        .Bind(builder.Configuration.GetSection(Platform.Application.Configuration.AuthenticationOptions.SectionName))
        .Validate(options => options.SessionDurationMinutes > 0, "Authentication:SessionDurationMinutes must be greater than zero.")
        .Validate(options => options.LockoutThreshold > 0, "Authentication:LockoutThreshold must be greater than zero.")
        .Validate(options => options.LockoutDurationMinutes > 0, "Authentication:LockoutDurationMinutes must be greater than zero.")
        .Validate(options => options.MaxConcurrentSessions > 0, "Authentication:MaxConcurrentSessions must be greater than zero.")
        .ValidateOnStart();
    builder.Services
        .AddOptions<TenantOptions>()
        .Bind(builder.Configuration.GetSection(TenantOptions.SectionName))
        .Validate(options => options.Id != Guid.Empty, "Tenant:Id must be a non-empty GUID.")
        .ValidateOnStart();
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
    var rawConnStr = builder.Configuration["Database:ConnectionString"]
               ?? builder.Configuration.GetConnectionString("Default")
               ?? builder.Configuration["DATABASE_URL"];
    var connStr = PostgresConnectionStringNormalizer.Normalize(rawConnStr);

    builder.Services.AddDbContext<PlatformDbContext>(opts =>
    {
        opts.ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.PendingModelChangesWarning));
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
    // Forwarded Headers (Cloud Load Balancer / Reverse Proxy SSL & IP forwarding)
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Authentication + CSRF
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddAuthentication("Platform")
        .AddCookie("Platform", opts =>
        {
            opts.Cookie.Name = "__ap_session";
            opts.Cookie.HttpOnly = true;
            opts.Cookie.SameSite = builder.Environment.IsProduction() ? SameSiteMode.None : SameSiteMode.Lax;
            opts.Cookie.SecurePolicy = builder.Environment.IsProduction()
                ? CookieSecurePolicy.Always
                : CookieSecurePolicy.SameAsRequest;
            opts.SlidingExpiration = false;

            // Return status codes for APIs instead of redirecting to HTML pages.
            opts.Events.OnRedirectToLogin = ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            opts.Events.OnRedirectToAccessDenied = ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
            opts.Events.OnValidatePrincipal = async ctx =>
            {
                var principal = ctx.Principal;
                var sidValue = principal?.FindFirst("sid")?.Value;
                var subValue = principal?.FindFirst("sub")?.Value;
                var claimedAdmin = principal?.HasClaim("platform_admin", "true") == true;

                var hasSessionId = Guid.TryParse(sidValue, out var sessionId);
                var hasUserId = Guid.TryParse(subValue, out var userId);
                ValidatedSession? validatedSession = null;

                if (hasSessionId && hasUserId)
                {
                    try
                    {
                        validatedSession = await ctx.HttpContext.RequestServices
                            .GetRequiredService<AuthService>()
                            .ValidateSessionAsync(sessionId, ctx.HttpContext.RequestAborted);
                    }
                    catch (Exception ex)
                    {
                        var logger = ctx.HttpContext.RequestServices.GetService<ILogger<Program>>();
                        logger?.LogError(ex, "Failed to validate session during principal validation.");
                    }
                }

                if (validatedSession is null ||
                    validatedSession.UserId != userId ||
                    validatedSession.IsPlatformAdmin != claimedAdmin)
                {
                    ctx.RejectPrincipal();
                    await ctx.HttpContext.SignOutAsync("Platform");
                }
            };
        });

    builder.Services.AddAuthorization(options =>
    {
        options.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
        options.AddPolicy("PlatformAdmin", policy => policy
            .RequireAuthenticatedUser()
            .RequireClaim("platform_admin", "true"));
    });

    builder.Services.AddAntiforgery(opts =>
    {
        opts.HeaderName = "X-CSRF-TOKEN";
        opts.Cookie.Name = "__ap_csrf";
        opts.Cookie.SameSite = builder.Environment.IsProduction() ? SameSiteMode.None : SameSiteMode.Strict;
        opts.Cookie.SecurePolicy = builder.Environment.IsProduction() ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
        opts.Cookie.HttpOnly = true;
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Rate Limiting (Tiered Policies: Login, Tenant API, Anonymous IP, Webhooks)
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddPlatformRateLimiting(builder.Configuration);
    builder.Services.AddHostedService<Platform.Api.Services.EnvironmentValidationHostedService>();

    // ─────────────────────────────────────────────────────────────────────────
    // CORS
    // ─────────────────────────────────────────────────────────────────────────
    var rawOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                      ?? ["http://localhost:3000"];

    var allowedOrigins = rawOrigins
        .Where(o => !string.IsNullOrWhiteSpace(o))
        .SelectMany(o =>
        {
            var trimmed = o.Trim();
            if (trimmed.StartsWith("http://") || trimmed.StartsWith("https://"))
            {
                return new[] { trimmed };
            }
            return new[] { $"https://{trimmed}", $"http://{trimmed}" };
        })
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    builder.Services.AddCors(opts => opts.AddDefaultPolicy(policy =>
        policy.SetIsOriginAllowed(_ => true)
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

    // Phase 5 extension providers. Keep this list identical to Platform.Worker/Program.cs so
    // the API and worker agree on what is validatable, and keep Fallback registered last.
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.HuggingFaceCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.PerplexityCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.CohereCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.FireworksAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.ReplicateCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.OpenRouterCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.XaiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.CerebrasCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.TavilyCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.FalAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.JinaAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.KlingAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.RunwayMlCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.RunPodCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.GoogleGeminiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.ElevenLabsCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.TogetherAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.MistralCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.StabilityAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.Ai21CredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.AssemblyAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.DeepgramCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.LeonardoAiCredentialValidator>();
    builder.Services.AddTransient<Platform.Application.Contracts.ICredentialValidator, Platform.Infrastructure.Validators.AzureOpenAiCredentialValidator>();

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
    builder.Services.AddHostedService<Platform.Worker.Workers.RepositoryAcquisitionWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.SnapshotAnalysisWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.StaleJobSweepWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.CredentialValidationWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.IncidentEngineWorker>();

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
    builder.Services.AddScoped<ScanReportBuilderService>();
    builder.Services.AddSingleton<SecurityReportFormatterRegistry>();
    builder.Services.AddScoped<IScanToolHealthService, ScanToolHealthService>();
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
        if (options.RuntimeMode == ScannerRuntimeMode.Disabled)
        {
            return new UnavailableScannerRuntime(
                sp.GetRequiredService<ILogger<UnavailableScannerRuntime>>());
        }

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

    // Phase 9 — Continuous Security Scan Campaigns & Observability
    builder.Services.Configure<CampaignSchedulerOptions>(builder.Configuration.GetSection(CampaignSchedulerOptions.SectionName));
    builder.Services.AddSingleton<ICampaignScheduleCalculator, CampaignScheduleCalculator>();
    builder.Services.AddScoped<IScanCampaignService, ScanCampaignService>();
    builder.Services.AddScoped<ICampaignObservabilityService, CampaignObservabilityService>();

    // SPEC-008 — Pluggable Scanner Tool Adapters & Registry
    builder.Services.AddSingleton<Platform.Application.Scanning.Services.IFindingFingerprintService, Platform.Application.Scanning.Services.FindingFingerprintService>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.HttpxOutputParser>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.NucleiOutputParser>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.SubfinderOutputParser>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.JsMinerOutputParser>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.BugHunterOutputParser>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.SemgrepOutputParser>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.TruffleHogOutputParser>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.HttpxAdapter>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.NucleiAdapter>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.SubfinderAdapter>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.JsMinerAdapter>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.SemgrepAdapter>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.TruffleHogAdapter>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolRegistry, Platform.Application.Scanning.Adapters.ScanToolRegistry>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Planning.IScanPlanningEngine, Platform.Application.Scanning.Planning.ScanPlanningEngine>();
    builder.Services.AddSingleton<Platform.Application.Scanning.JavaScript.IJsDiscoveryEngine, Platform.Application.Scanning.JavaScript.JsDiscoveryEngine>();
    builder.Services.AddSingleton<Platform.Application.Scanning.JavaScript.IJsAstAnalyzer, Platform.Application.Scanning.JavaScript.JsAstAnalyzer>();
    builder.Services.AddSingleton<Platform.Application.Scanning.JavaScript.IJsSecretAnalyzer, Platform.Application.Scanning.JavaScript.JsSecretAnalyzer>();
    builder.Services.AddSingleton<Platform.Application.Scanning.JavaScript.IJsDataFlowAnalyzer, Platform.Application.Scanning.JavaScript.JsDataFlowAnalyzer>();
    builder.Services.AddSingleton<Platform.Application.Scanning.JavaScript.IUnifiedJsAnalyzer, Platform.Application.Scanning.JavaScript.UnifiedJsAnalyzer>();
    builder.Services.AddSingleton<Platform.Application.Scanning.JavaScript.IJsAiEnrichmentService, Platform.Application.Scanning.JavaScript.JsAiEnrichmentService>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Verification.IVerificationPlanner, Platform.Application.Scanning.Verification.VerificationPlanner>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Orchestration.IDeploymentConcurrencyGate, Platform.Application.Scanning.Orchestration.DeploymentConcurrencyGate>();
    builder.Services.AddSingleton<Platform.Application.Scanning.Orchestration.IDeploymentScanOrchestrator, Platform.Application.Scanning.Orchestration.DeploymentScanOrchestrator>();
    builder.Services.AddScoped<Platform.Application.Scanning.Audit.IScanPlanAuditService, Platform.Application.Scanning.Audit.ScanPlanAuditService>();
    builder.Services.AddScoped<Platform.Application.Scanning.Execution.IScanExecutionEngine, Platform.Application.Scanning.Execution.ScanExecutionEngine>();

    // Step 9.4 — Deployment Webhook Wiring
    // IDeploymentLeaseStore was previously unregistered (concrete gate relied on it).
    builder.Services.AddSingleton<Platform.Application.Scanning.Orchestration.IDeploymentLeaseStore, Platform.Infrastructure.Scanning.InMemoryDeploymentLeaseStore>();
    builder.Services.AddScoped<Platform.Application.Scanning.Verification.IApplicationTargetResolver, Platform.Infrastructure.Scanning.DatabaseApplicationTargetResolver>();
    builder.Services.AddScoped<Platform.Application.Scanning.Verification.IDeploymentScanJobEnqueuer, Platform.Infrastructure.Scanning.DatabaseDeploymentScanJobEnqueuer>();
    builder.Services.AddScoped<Platform.Application.Scanning.Verification.IDeploymentWebhookHandler, Platform.Application.Scanning.Verification.DeploymentWebhookHandler>();
    builder.Services.AddScoped<Platform.Application.Scanning.Verification.IRegisteredApplicationService, Platform.Infrastructure.Scanning.RegisteredApplicationService>();

    // Phase 10 — Operations AI & Observability
    builder.Services.AddSingleton<Platform.Application.Operations.IOperationalPromptSanitizer, Platform.Infrastructure.Operations.OperationalPromptSanitizer>();
    builder.Services.AddScoped<Platform.Application.Operations.IIncidentEngineService, Platform.Infrastructure.Operations.IncidentEngineService>();
    builder.Services.AddScoped<Platform.Application.Operations.IAiOperationalDiagnosisService, Platform.Infrastructure.Operations.AiOperationalDiagnosisService>();
    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3 Infrastructure Adapters
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddScoped<IGitHubCredentialProvider, Platform.Infrastructure.Adapters.GitHub.GitHubAppCredentialProvider>();
    builder.Services.AddScoped<IGitHubCredentialProvider, Platform.Infrastructure.Adapters.GitHub.GitHubPatCredentialProvider>();
    builder.Services.AddScoped<IRepositoryProvider, Platform.Infrastructure.Adapters.GitHub.GitHubRepositoryProvider>();
    builder.Services.AddHttpClient("GitHubArchive");

    builder.Services.AddScoped<IObjectStore>(sp =>
    {
        var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ObjectStoreOptions>>().Value;
        var env = sp.GetRequiredService<IHostEnvironment>();
        if (env.IsDevelopment() || (string.IsNullOrWhiteSpace(opts.ServiceUrl) && string.IsNullOrWhiteSpace(opts.AccessKeyId)))
        {
            return new Platform.Infrastructure.Adapters.ObjectStore.FileSystemObjectStore(
                env,
                sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ObjectStoreOptions>>(),
                sp.GetRequiredService<ILogger<Platform.Infrastructure.Adapters.ObjectStore.FileSystemObjectStore>>());
        }
        return new Platform.Infrastructure.Adapters.ObjectStore.S3ObjectStoreAdapter(
            sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ObjectStoreOptions>>(),
            sp.GetRequiredService<ILogger<Platform.Infrastructure.Adapters.ObjectStore.S3ObjectStoreAdapter>>());
    });

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
    builder.Services.AddSingleton<ITenantContext, ConfiguredTenantContext>();
    builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();
    builder.Services.AddScoped<ICurrentUserContextProvider>(sp =>
        (HttpCurrentUserContext)sp.GetRequiredService<ICurrentUserContext>());

    // ─────────────────────────────────────────────────────────────────────────
    // OpenTelemetry
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService("APIHunterPlatform"))
        .WithTracing(t => t.AddAspNetCoreInstrumentation()
                           .AddSource(Platform.Application.Observability.PlatformTracing.ActivitySourceName))
        .WithMetrics(m => m.AddAspNetCoreInstrumentation()
                           .AddMeter(Platform.Application.Observability.PlatformMetrics.MeterName));

    // ─────────────────────────────────────────────────────────────────────────
    // Controllers + OpenAPI
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.AddControllersWithViews(options =>
        options.Filters.Add<ApiAntiforgeryAuthorizationFilter>());
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(opts =>
    {
        opts.SwaggerDoc("v1", new() { Title = "APIHunter Security Platform API", Version = "v1" });
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Background Workers (Embedded in API for Render Free Tier $0 hosting)
    // ─────────────────────────────────────────────────────────────────────────
    builder.Services.Configure<CampaignSchedulerOptions>(builder.Configuration.GetSection(CampaignSchedulerOptions.SectionName));
    builder.Services.Configure<ScanJobConsumerOptions>(builder.Configuration.GetSection(ScanJobConsumerOptions.SectionName));
    builder.Services.AddSingleton<ScanJobHeartbeatService>();

    builder.Services.AddHostedService<Platform.Worker.Workers.RepositoryAcquisitionWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.SnapshotAnalysisWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.StaleJobSweepWorker>();
    builder.Services.AddHostedService<Platform.Infrastructure.Workers.AiInvestigationWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.CredentialValidationWorker>();
    builder.Services.AddHostedService<Platform.Infrastructure.Workers.SecurityScanJobConsumerWorker>();
    builder.Services.AddHostedService<Platform.Infrastructure.Workers.CampaignSchedulerWorker>();
    builder.Services.AddHostedService<Platform.Worker.Workers.IncidentEngineWorker>();

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
    app.UseForwardedHeaders();
    app.UseMiddleware<ErrorHandlingMiddleware>();
    app.UseMiddleware<CorrelationIdMiddleware>();
    Platform.Api.Middleware.SecurityHeadersMiddlewareExtensions.UsePlatformSecurityHeaders(app);
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
    Platform.Api.Extensions.HealthProbesExtensions.MapPlatformHealthProbes(app);
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
