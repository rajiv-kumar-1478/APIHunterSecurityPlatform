using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

public class ScanToolHealthService : IScanToolHealthService
{
    private readonly ScanToolRegistryService? _registryService;
    private readonly IPlatformDbContext _dbContext;
    private readonly IToolRuntimeVerifier _runtimeVerifier;
    private readonly ScannerRuntimeOptions _options;
    private readonly IEnforcedEgressGateway? _egressGateway;
    private readonly HttpClient? _httpClient;
    private readonly ILogger<ScanToolHealthService> _logger;

    public ScanToolHealthService(
        ScanToolRegistryService? registryService = null,
        ILogger<ScanToolHealthService>? logger = null,
        IPlatformDbContext? dbContext = null,
        IToolRuntimeVerifier? runtimeVerifier = null,
        ScannerRuntimeOptions? options = null,
        IEnforcedEgressGateway? egressGateway = null,
        HttpClient? httpClient = null)
    {
        _registryService = registryService;
        _logger = logger ?? NullLogger<ScanToolHealthService>.Instance;
        _dbContext = dbContext!;
        _runtimeVerifier = runtimeVerifier ?? new ToolRuntimeVerifier(NullLogger<ToolRuntimeVerifier>.Instance);
        _options = options ?? new ScannerRuntimeOptions();
        _egressGateway = egressGateway;
        _httpClient = httpClient;
    }

    public async Task<ScanToolDto> CheckToolHealthAsync(string toolKey, CancellationToken ct = default)
    {
        var normalizedKey = toolKey.Trim().ToLowerInvariant();

        if (_dbContext == null)
        {
            if (_registryService != null)
            {
                var allTools = await _registryService.GetAllToolsAsync(ct);
                var existingDto = allTools.FirstOrDefault(t => string.Equals(t.ToolKey, toolKey, StringComparison.OrdinalIgnoreCase));
                if (existingDto != null) return existingDto;
            }

            return new ScanToolDto(
                Id: Guid.Empty,
                ToolKey: toolKey,
                DisplayName: toolKey,
                Version: "unregistered",
                Executable: toolKey,
                Enabled: false,
                Required: false,
                Capabilities: Array.Empty<string>(),
                HealthStatus: ToolHealthStatus.Missing,
                LastHealthCheckUtc: DateTime.UtcNow
            );
        }

        var toolEntity = await _dbContext.SecurityScanTools.FirstOrDefaultAsync(t => t.ToolKey.ToLower() == normalizedKey, ct);

        if (toolEntity == null)
        {
            _logger.LogWarning("Requested health check for unregistered tool '{ToolKey}'.", toolKey);
            return new ScanToolDto(
                Id: Guid.Empty,
                ToolKey: toolKey,
                DisplayName: toolKey,
                Version: "unregistered",
                Executable: toolKey,
                Enabled: false,
                Required: false,
                Capabilities: Array.Empty<string>(),
                HealthStatus: ToolHealthStatus.Missing,
                LastHealthCheckUtc: DateTime.UtcNow
            );
        }

        var probeResult = await _runtimeVerifier.ProbeToolAsync(toolEntity, ct);
        var oldStatus = toolEntity.HealthStatus;
        var newStatus = probeResult.Success ? ToolHealthStatus.Healthy : ToolHealthStatus.Degraded;

        if (oldStatus != newStatus)
        {
            _logger.LogWarning("Tool '{ToolKey}' health status changed from '{OldStatus}' to '{NewStatus}' (Probe: {Probe}, Reason: {ErrorCode}).",
                toolEntity.ToolKey, oldStatus, newStatus, probeResult.ProbeName, probeResult.ErrorCode);

            toolEntity.HealthStatus = newStatus;
            toolEntity.LastHealthCheckUtc = DateTime.UtcNow;
            toolEntity.UpdatedAtUtc = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync(ct);
        }

        return MapToDto(toolEntity);
    }

    public async Task<IReadOnlyList<ScanToolDto>> GetAllToolStatusAsync(CancellationToken ct = default)
    {
        return _registryService != null ? await _registryService.GetAllToolsAsync(ct) : Array.Empty<ScanToolDto>();
    }

    public async Task<ScannerRuntimeHealthDto> GetScannerRuntimeHealthAsync(CancellationToken ct = default)
    {
        var (dockerAvailable, dockerVersion) = CheckDockerDaemon();
        var gatewayHealthy = _egressGateway == null || await _egressGateway.IsGatewayHealthyAsync(ct);

        var activeJobsCount = 0;
        if (_dbContext != null)
        {
            try
            {
                activeJobsCount = await _dbContext.SecurityScanJobs
                    .CountAsync(j => j.Status == SecurityScanJobStatus.Running || j.Status == SecurityScanJobStatus.Queued, ct);
            }
            catch
            {
                // Fallback for in-memory or uninitialized test DBs
            }
        }

        bool isRuntimeAvailable;
        string runtimeVersion;

        switch (_options.RuntimeMode)
        {
            case ScannerRuntimeMode.LocalDocker:
                isRuntimeAvailable = dockerAvailable;
                runtimeVersion = dockerVersion;
                break;

            case ScannerRuntimeMode.CloudManagedContainer:
                var cloudHealth = await CheckCloudScannerHealthAsync(ct);
                isRuntimeAvailable = cloudHealth.Available;
                runtimeVersion = cloudHealth.Version;
                break;

            case ScannerRuntimeMode.UnsafeLocalProcessFallback:
                isRuntimeAvailable = _options.AllowUnsafeProcessFallback;
                runtimeVersion = "Unsafe Local Process (Dev Only)";
                break;

            default:
                isRuntimeAvailable = dockerAvailable;
                runtimeVersion = dockerVersion;
                break;
        }

        var readyForScans = isRuntimeAvailable && gatewayHealthy && _options.EnforceImageProvenance;

        return new ScannerRuntimeHealthDto(
            Runtime: new RuntimeHealthInfo(
                Mode: _options.RuntimeMode.ToString(),
                Available: isRuntimeAvailable,
                Version: runtimeVersion
            ),
            Provenance: new ProvenanceHealthInfo(
                ImageDigestRequired: _options.EnforceImageProvenance,
                TrustedRegistries: _options.TrustedImageRegistries
            ),
            Egress: new EgressHealthInfo(
                Mode: _options.EgressGatewayMode.ToString(),
                Enforced: _options.EgressGatewayMode == EgressGatewayMode.EnforcedGateway,
                GatewayHealthy: gatewayHealthy,
                GatewayEndpoint: _options.EgressGatewayEndpoint
            ),
            Limits: new RuntimeLimitsInfo(
                CpuCores: _options.MaxCpuCores,
                MemoryBytes: _options.MaxMemoryBytes,
                Pids: _options.MaxPids,
                ScratchBytes: _options.MaxScratchDiskBytes,
                TimeoutSeconds: (int)_options.ExecutionTimeout.TotalSeconds
            ),
            ActiveJobsCount: activeJobsCount,
            ReadyForScans: readyForScans,
            LastHealthCheckUtc: DateTime.UtcNow
        );
    }

    private async Task<(bool Available, string Version)> CheckCloudScannerHealthAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_options.HostedScannerServiceEndpoint) || string.IsNullOrWhiteSpace(_options.HostedScannerServiceKey))
        {
            return (false, "Cloud Scanner Service Unconfigured");
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(3));

            var client = _httpClient;
            var shouldDispose = false;

            if (client == null)
            {
                client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
                shouldDispose = true;
            }

            try
            {
                var baseUri = new Uri(_options.HostedScannerServiceEndpoint.TrimEnd('/') + "/");
                var requestUri = new Uri(baseUri, "health/ready");

                using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
                request.Headers.Add("X-Scanner-Service-Key", _options.HostedScannerServiceKey);

                using var response = await client.SendAsync(request, cts.Token);
                if (response.IsSuccessStatusCode)
                {
                    return (true, "Cloud Managed Scanner Service Active");
                }

                _logger.LogWarning("Cloud scanner service returned degraded HTTP status {StatusCode}.", (int)response.StatusCode);
                return (false, $"Cloud Scanner Service Degraded (HTTP {(int)response.StatusCode})");
            }
            finally
            {
                if (shouldDispose)
                {
                    client.Dispose();
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Cloud scanner service health probe timed out after 3 seconds.");
            return (false, "Cloud Scanner Service Timed Out");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cloud scanner service health probe failed at endpoint '{Endpoint}'.", _options.HostedScannerServiceEndpoint);
            return (false, "Cloud Scanner Service Unreachable");
        }
    }

    private static (bool Available, string Version) CheckDockerDaemon()
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "docker",
                    Arguments = "info",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            var exited = proc.WaitForExit(3000);

            if (exited && proc.ExitCode == 0)
            {
                return (true, "Docker Daemon Active");
            }

            return (false, "Docker Daemon Offline / Socket Unavailable");
        }
        catch
        {
            return (false, "Docker CLI Not Installed / Socket Unavailable");
        }
    }

    private static ScanToolDto MapToDto(SecurityScanTool tool) => new(
        Id: tool.Id,
        ToolKey: tool.ToolKey,
        DisplayName: tool.DisplayName,
        Version: tool.Version,
        Executable: tool.Executable,
        Enabled: tool.Enabled,
        Required: tool.Required,
        Capabilities: Array.Empty<string>(),
        HealthStatus: tool.HealthStatus,
        LastHealthCheckUtc: tool.LastHealthCheckUtc,
        ContainerImageRepository: tool.ContainerImageRepository,
        ContainerImageDigest: tool.ContainerImageDigest
    );
}
