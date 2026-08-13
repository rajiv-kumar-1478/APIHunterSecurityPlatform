using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

public class ScanToolHealthService : IScanToolHealthService
{
    private readonly ScanToolRegistryService _registryService;
    private readonly ILogger<ScanToolHealthService> _logger;

    public ScanToolHealthService(ScanToolRegistryService registryService, ILogger<ScanToolHealthService> logger)
    {
        _registryService = registryService;
        _logger = logger;
    }

    public async Task<ScanToolDto> CheckToolHealthAsync(string toolKey, CancellationToken ct = default)
    {
        var allTools = await _registryService.GetAllToolsAsync(ct);
        foreach (var tool in allTools)
        {
            if (string.Equals(tool.ToolKey, toolKey, StringComparison.OrdinalIgnoreCase))
            {
                return tool;
            }
        }

        _logger.LogWarning("Requested health check for unregistered tool '{ToolKey}'.", toolKey);
        return new ScanToolDto(
            Id: Guid.Empty,
            ToolKey: toolKey,
            DisplayName: toolKey,
            Version: "unregistered",
            Enabled: false,
            Required: false,
            Capabilities: Array.Empty<string>(),
            HealthStatus: ToolHealthStatus.Missing,
            LastHealthCheckUtc: DateTime.UtcNow
        );
    }

    public async Task<IReadOnlyList<ScanToolDto>> GetAllToolStatusAsync(CancellationToken ct = default)
    {
        return await _registryService.GetAllToolsAsync(ct);
    }
}
