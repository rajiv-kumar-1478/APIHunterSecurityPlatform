using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Adapters.Detection;
using Platform.Infrastructure.Adapters.GitHub;
using Platform.Infrastructure.Adapters.ObjectStore;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Scanning;
using Platform.Infrastructure.Tenancy;
using Platform.Infrastructure.Workers;
using Platform.Worker.Workers;

var builder = Host.CreateApplicationBuilder(args);

if (builder.Environment.IsProduction())
{
    ProductionSecurityConfigurationValidator.Validate(builder.Configuration, requireHttps: false);
}

builder.Services
    .AddOptions<TenantOptions>()
    .Bind(builder.Configuration.GetSection(TenantOptions.SectionName))
    .Validate(options => options.Id != Guid.Empty, "Tenant:Id must be a non-empty GUID.")
    .ValidateOnStart();
builder.Services.Configure<DatabaseOptions>(builder.Configuration.GetSection(DatabaseOptions.SectionName));
builder.Services.Configure<GitHubOptions>(builder.Configuration.GetSection(GitHubOptions.SectionName));
builder.Services.Configure<ObjectStoreOptions>(builder.Configuration.GetSection(ObjectStoreOptions.SectionName));
builder.Services.Configure<DetectionOptions>(builder.Configuration.GetSection(DetectionOptions.SectionName));
builder.Services
    .AddOptions<CampaignSchedulerOptions>()
    .Bind(builder.Configuration.GetSection(CampaignSchedulerOptions.SectionName))
    .Validate(options => options.TickIntervalSeconds > 0,
        "CampaignScheduler:TickIntervalSeconds must be greater than zero.")
    .Validate(options => options.MaxCampaignsPerTick > 0,
        "CampaignScheduler:MaxCampaignsPerTick must be greater than zero.")
    .Validate(options => options.RecoveryIntervalSeconds > 0,
        "CampaignScheduler:RecoveryIntervalSeconds must be greater than zero.")
    .Validate(options => options.HeartbeatIntervalSeconds > 0,
        "CampaignScheduler:HeartbeatIntervalSeconds must be greater than zero.")
    .Validate(options => options.StuckJobThresholdMinutes > 0,
        "CampaignScheduler:StuckJobThresholdMinutes must be greater than zero.")
    .Validate(options => 3L * options.HeartbeatIntervalSeconds <= 60L * options.StuckJobThresholdMinutes,
        "CampaignScheduler must allow at least three heartbeat opportunities before stale-job recovery.")
    .ValidateOnStart();
builder.Services.Configure<ScanJobConsumerOptions>(builder.Configuration.GetSection(ScanJobConsumerOptions.SectionName));

var connectionString = builder.Configuration["Database:ConnectionString"]
    ?? builder.Configuration.GetConnectionString("Default")
    ?? builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Host=localhost;Database=apihunter_platform;Username=postgres;Password=postgres";

builder.Services.AddDbContext<PlatformDbContext>(options =>
    options.UseNpgsql(connectionString, b => b.MigrationsAssembly("Platform.Infrastructure")));

builder.Services.AddScoped<IPlatformDbContext>(sp => sp.GetRequiredService<PlatformDbContext>());

var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName(builder.Configuration["DataProtection:ApplicationName"] ?? "APIHunterPlatform");
var dataProtectionKeyPath = builder.Configuration["DataProtection:KeyPath"];
if (!string.IsNullOrWhiteSpace(dataProtectionKeyPath))
{
    dataProtection.PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeyPath));
}

builder.Services.AddSingleton<ITenantContext, ConfiguredTenantContext>();
builder.Services.AddScoped<WorkerUserContext>();
builder.Services.AddScoped<ICurrentUserContext>(sp => sp.GetRequiredService<WorkerUserContext>());
builder.Services.AddScoped<ICurrentUserContextProvider>(sp => sp.GetRequiredService<WorkerUserContext>());
builder.Services.AddScoped<IAuditService, AuditService>();

builder.Services.AddHttpClient();
builder.Services.AddScoped<IGitHubCredentialProvider, GitHubAppCredentialProvider>();
builder.Services.AddScoped<IRepositoryProvider, GitHubRepositoryProvider>();
builder.Services.AddScoped<IObjectStore, FileSystemObjectStore>();
builder.Services.AddScoped<ISecretDetector, RegexSecretDetector>();

builder.Services.AddScoped<RepositoryAcquisitionService>();
builder.Services.AddScoped<SnapshotService>();
builder.Services.AddScoped<SecretDetectionService>();
builder.Services.AddScoped<CandidateService>();
builder.Services.AddScoped<JobOrchestrationService>();

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

// Phase 5 extension providers. Keep this list identical to Platform.Api/Program.cs so the API
// and worker agree on what is validatable, and keep Fallback registered last.
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

var riskPolicy = new RiskPolicyOptions();
builder.Configuration.GetSection(RiskPolicyOptions.SectionName).Bind(riskPolicy);
builder.Services.AddSingleton(riskPolicy);
builder.Services.AddSingleton<RiskEngine>();
builder.Services.AddScoped<SecurityFindingService>();

builder.Services.AddScoped<ScanToolRegistryService>();
builder.Services.AddScoped<ScanJobService>();
builder.Services.AddScoped<ScanPostExecutionProcessor>();
builder.Services.AddTransient<Func<string, IGenericCliToolAdapter>>(sp => toolKey =>
    new GenericCliToolAdapter(toolKey, sp.GetRequiredService<ILogger<GenericCliToolAdapter>>()));
builder.Services.AddScoped<IScanWorker, GenericScanWorker>();
builder.Services.AddSingleton<ScanJobHeartbeatService>();

var scannerOptions = builder.Configuration.GetSection("ScannerRuntime").Get<ScannerRuntimeOptions>()
    ?? new ScannerRuntimeOptions();
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

builder.Services.AddSingleton<IDatabaseErrorClassifier, PostgreSqlDatabaseErrorClassifier>();
builder.Services.AddScoped<ICampaignScheduleCalculator, CampaignScheduleCalculator>();
builder.Services.AddScoped<ICampaignDispatchService, CampaignDispatchService>();

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

// Step 9.4 — Deployment Webhook Wiring (Worker needs IDeploymentLeaseStore for concurrency gate)
builder.Services.AddSingleton<Platform.Application.Scanning.Orchestration.IDeploymentLeaseStore, Platform.Infrastructure.Scanning.InMemoryDeploymentLeaseStore>();
builder.Services.AddScoped<Platform.Application.Scanning.Verification.IApplicationTargetResolver, Platform.Infrastructure.Scanning.DatabaseApplicationTargetResolver>();
builder.Services.AddScoped<Platform.Application.Scanning.Verification.IDeploymentScanJobEnqueuer, Platform.Infrastructure.Scanning.DatabaseDeploymentScanJobEnqueuer>();
builder.Services.AddScoped<Platform.Application.Scanning.Verification.IDeploymentWebhookHandler, Platform.Application.Scanning.Verification.DeploymentWebhookHandler>();
builder.Services.AddScoped<Platform.Application.Scanning.Verification.IRegisteredApplicationService, Platform.Infrastructure.Scanning.RegisteredApplicationService>();

builder.Services.AddHostedService<RepositoryAcquisitionWorker>();
builder.Services.AddHostedService<SnapshotAnalysisWorker>();
builder.Services.AddHostedService<StaleJobSweepWorker>();
builder.Services.AddHostedService<AiInvestigationWorker>();
builder.Services.AddHostedService<CredentialValidationWorker>();
builder.Services.AddHostedService<SecurityScanJobConsumerWorker>();
builder.Services.AddHostedService<CampaignSchedulerWorker>();

var host = builder.Build();
host.Run();

public class WorkerUserContext : ICurrentUserContext, ICurrentUserContextProvider
{
    private readonly string _correlationId = Guid.NewGuid().ToString("N");

    public Guid? UserId => null;
    public string? SessionId => null;
    public bool IsAuthenticated => false;
    public bool IsPlatformAdmin => false;
    public string CorrelationId => _correlationId;
    public string IpAddress => "127.0.0.1";
}
