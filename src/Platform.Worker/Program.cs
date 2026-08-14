using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Infrastructure.Adapters.Detection;
using Platform.Infrastructure.Adapters.GitHub;
using Platform.Infrastructure.Adapters.ObjectStore;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Workers;
using Platform.Worker.Workers;

var builder = Host.CreateApplicationBuilder(args);

// Configuration options
builder.Services.Configure<DatabaseOptions>(builder.Configuration.GetSection(DatabaseOptions.SectionName));
builder.Services.Configure<GitHubOptions>(builder.Configuration.GetSection(GitHubOptions.SectionName));
builder.Services.Configure<ObjectStoreOptions>(builder.Configuration.GetSection(ObjectStoreOptions.SectionName));
builder.Services.Configure<DetectionOptions>(builder.Configuration.GetSection(DetectionOptions.SectionName));

// EF Core DbContext
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? "Host=localhost;Database=apihunter_platform;Username=postgres;Password=postgres";

builder.Services.AddDbContext<PlatformDbContext>(options =>
    options.UseNpgsql(connectionString, b => b.MigrationsAssembly("Platform.Infrastructure")));

builder.Services.AddScoped<IPlatformDbContext>(sp => sp.GetRequiredService<PlatformDbContext>());

// Data Protection
builder.Services.AddDataProtection();

// Null audit service for worker context if no active user session
builder.Services.AddScoped<WorkerUserContext>();
builder.Services.AddScoped<ICurrentUserContext>(sp => sp.GetRequiredService<WorkerUserContext>());
builder.Services.AddScoped<ICurrentUserContextProvider>(sp => sp.GetRequiredService<WorkerUserContext>());
builder.Services.AddScoped<IAuditService, AuditService>();

// Infrastructure Adapters
builder.Services.AddHttpClient();
builder.Services.AddScoped<IGitHubCredentialProvider, GitHubAppCredentialProvider>();
builder.Services.AddScoped<IRepositoryProvider, GitHubRepositoryProvider>();
builder.Services.AddScoped<IObjectStore, FileSystemObjectStore>();
builder.Services.AddScoped<ISecretDetector, RegexSecretDetector>();

// Application Services
builder.Services.AddScoped<RepositoryAcquisitionService>();
builder.Services.AddScoped<SnapshotService>();
builder.Services.AddScoped<SecretDetectionService>();
builder.Services.AddScoped<CandidateService>();
builder.Services.AddScoped<JobOrchestrationService>();

// Phase 5 Application Services, Validation Plugins & Workers
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

// Phase 6 Services
var riskPolicy = new RiskPolicyOptions();
builder.Configuration.GetSection(RiskPolicyOptions.SectionName).Bind(riskPolicy);
builder.Services.AddSingleton(riskPolicy);
builder.Services.AddSingleton<RiskEngine>();
builder.Services.AddScoped<SecurityFindingService>();

// Phase 9 — Campaign Scheduler
builder.Services.Configure<CampaignSchedulerOptions>(builder.Configuration.GetSection(CampaignSchedulerOptions.SectionName));
builder.Services.AddScoped<ICampaignScheduleCalculator, CampaignScheduleCalculator>();
builder.Services.AddScoped<ICampaignDispatchService, CampaignDispatchService>();

// SPEC-008 — Pluggable Scanner Tool Adapters & Registry
builder.Services.AddSingleton<Platform.Application.Scanning.Services.IFindingFingerprintService, Platform.Application.Scanning.Services.FindingFingerprintService>();
builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.HttpxOutputParser>();
builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.NucleiOutputParser>();
builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.SubfinderOutputParser>();
builder.Services.AddSingleton<Platform.Application.Scanning.Parsers.JsMinerOutputParser>();
builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.HttpxAdapter>();
builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.NucleiAdapter>();
builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.SubfinderAdapter>();
builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolAdapter, Platform.Application.Scanning.Adapters.JsMinerAdapter>();
builder.Services.AddSingleton<Platform.Application.Scanning.Adapters.IScanToolRegistry, Platform.Application.Scanning.Adapters.ScanToolRegistry>();



// Hosted Workers
builder.Services.AddHostedService<RepositoryAcquisitionWorker>();
builder.Services.AddHostedService<SnapshotAnalysisWorker>();
builder.Services.AddHostedService<StaleJobSweepWorker>();
builder.Services.AddHostedService<Platform.Infrastructure.Workers.AiInvestigationWorker>();
builder.Services.AddHostedService<CredentialValidationWorker>();

// Phase 9 — Campaign Scheduler + Recovery Worker
builder.Services.AddHostedService<CampaignSchedulerWorker>();



var host = builder.Build();
host.Run();

// Worker identity context stub for automated background jobs
public class WorkerUserContext : ICurrentUserContext, ICurrentUserContextProvider
{
    public Guid? UserId => null;
    public string? SessionId => null;
    public bool IsAuthenticated => false;
    public bool IsPlatformAdmin => true;
    public string CorrelationId => Guid.NewGuid().ToString();
    public string IpAddress => "127.0.0.1";
}
