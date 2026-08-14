using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public class ScanToolRegistryService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ILogger<ScanToolRegistryService> _logger;

    public ScanToolRegistryService(IPlatformDbContext dbContext, ILogger<ScanToolRegistryService> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    private static readonly HashSet<string> ForbiddenShellInterpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "cmd.exe", "powershell", "powershell.exe", "bash", "sh", "zsh", "csh", "ksh", "wscript", "cscript", "python", "python.exe", "perl", "ruby"
    };

    public async Task<SecurityScanTool> RegisterToolAsync(
        string toolKey,
        string displayName,
        string version,
        bool required,
        IReadOnlyList<ToolCapability> capabilities,
        string? executable = null,
        CancellationToken ct = default)
    {
        toolKey = toolKey.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(executable))
        {
            throw new ArgumentException("Tool executable must be explicitly configured and cannot be empty.", nameof(executable));
        }

        var targetExecutable = executable.Trim();
        ValidateExecutableName(targetExecutable);

        var existing = await _dbContext.SecurityScanTools.FirstOrDefaultAsync(t => t.ToolKey == toolKey, ct);
        if (existing != null)
        {
            _logger.LogWarning("Tool key '{ToolKey}' already registered.", toolKey);
            throw new InvalidOperationException($"Tool key '{toolKey}' is already registered.");
        }

        var tool = new SecurityScanTool
        {
            Id = Guid.NewGuid(),
            ToolKey = toolKey,
            DisplayName = displayName,
            Version = version,
            Executable = targetExecutable,
            Required = required,
            Enabled = true,
            CapabilitiesJson = JsonSerializer.Serialize(capabilities.Select(c => c.ToString())),
            HealthStatus = ToolHealthStatus.Healthy,
            LastHealthCheckUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityScanTools.Add(tool);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("Tool '{ToolKey}' ({DisplayName}, v{Version}, exe: '{Executable}') successfully registered.", toolKey, displayName, version, tool.Executable);
        return tool;
    }

    public async Task<IReadOnlyList<ScanToolDto>> GetAllToolsAsync(CancellationToken ct = default)
    {
        var tools = await _dbContext.SecurityScanTools.AsNoTracking().ToListAsync(ct);
        return tools.Select(MapToDto).ToList();
    }

    public async Task<IReadOnlyDictionary<string, string>> GetAuthorizedManifestMapAsync(CancellationToken ct = default)
    {
        var tools = await _dbContext.SecurityScanTools.AsNoTracking().Where(t => t.Enabled).ToListAsync(ct);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var t in tools)
        {
            var key = t.ToolKey.Trim().ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(t.Executable))
            {
                map[key] = t.Executable.Trim();
            }
        }

        return map;
    }

    public async Task<IReadOnlyList<ScanToolDto>> GetToolsForCapabilitiesAsync(IEnumerable<ToolCapability> requiredCapabilities, CancellationToken ct = default)
    {
        var requiredCapStrings = requiredCapabilities.Select(c => c.ToString()).ToHashSet();
        var allTools = await _dbContext.SecurityScanTools.AsNoTracking().Where(t => t.Enabled).ToListAsync(ct);

        return allTools.Where(t =>
        {
            var caps = ParseCapabilities(t.CapabilitiesJson);
            return caps.Any(c => requiredCapStrings.Contains(c));
        }).Select(MapToDto).ToList();
    }

    public async Task<IReadOnlyList<ScanCapabilityDto>> GetCapabilityManifestAsync(CancellationToken ct = default)
    {
        var allTools = await GetAllToolsAsync(ct);

        var capabilities = Enum.GetValues<ToolCapability>();
        var manifest = new List<ScanCapabilityDto>();

        foreach (var cap in capabilities)
        {
            var capName = cap.ToString();
            var supportingTools = allTools
                .Where(t => t.Capabilities.Contains(capName, StringComparer.OrdinalIgnoreCase))
                .Select(t => t.ToolKey)
                .ToList();

            manifest.Add(new ScanCapabilityDto(
                CapabilityKey: capName,
                DisplayName: FormatDisplayName(capName),
                Description: GetCapabilityDescription(cap),
                AvailableTools: supportingTools
            ));
        }

        return manifest;
    }

    private static ScanToolDto MapToDto(SecurityScanTool tool) => new(
        Id: tool.Id,
        ToolKey: tool.ToolKey,
        DisplayName: tool.DisplayName,
        Version: tool.Version,
        Executable: tool.Executable ?? string.Empty,
        Enabled: tool.Enabled,
        Required: tool.Required,
        Capabilities: ParseCapabilities(tool.CapabilitiesJson),
        HealthStatus: tool.HealthStatus,
        LastHealthCheckUtc: tool.LastHealthCheckUtc,
        ContainerImageRepository: tool.ContainerImageRepository,
        ContainerImageDigest: tool.ContainerImageDigest
    );

    private static IReadOnlyList<string> ParseCapabilities(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string FormatDisplayName(string key) => string.Concat(key.Select((x, i) => i > 0 && char.IsUpper(x) ? " " + x : x.ToString()));

    private static string GetCapabilityDescription(ToolCapability cap) => cap switch
    {
        ToolCapability.SubdomainEnumeration => "Passive and active subdomain discovery across target domain assets.",
        ToolCapability.DnsResolution => "Mass DNS resolution and record verification.",
        ToolCapability.HttpProbing => "Fast HTTP/HTTPS web server probing and response header inspection.",
        ToolCapability.UrlCrawling => "Deep web spidering and JavaScript endpoint extraction.",
        ToolCapability.VulnerabilityScanning => "Template-based and signature security vulnerability scanning.",
        ToolCapability.Fuzzing => "Directory, parameter, and endpoint fuzzing.",
        ToolCapability.SecretScanning => "Repository and client bundle secret candidate discovery.",
        ToolCapability.Web3Analysis => "Smart contract and Web3 RPC security analysis.",
        ToolCapability.AiAssistedHunting => "LLM-assisted security vulnerability hypothesis generation and verification.",
        ToolCapability.ReportGeneration => "Normalized security assessment artifact and finding report generation.",
        _ => "Security intelligence scanning capability."
    };

    public static void ValidateExecutableName(string executable)
    {
        if (string.IsNullOrWhiteSpace(executable))
        {
            throw new ArgumentException("Tool executable name cannot be empty.", nameof(executable));
        }

        var trimmed = executable.Trim();
        if (trimmed.Contains("..") || trimmed.Contains('/') || trimmed.Contains('\\') || Path.IsPathRooted(trimmed))
        {
            throw new InvalidOperationException($"Security Violation: Executable '{executable}' contains prohibited path separators, path traversal, or absolute path specifiers.");
        }

        if (ForbiddenShellInterpreters.Contains(trimmed))
        {
            throw new InvalidOperationException($"Security Violation: Shell interpreter or command primitive '{executable}' is strictly prohibited as a security scanner executable.");
        }

        if (!System.Text.RegularExpressions.Regex.IsMatch(trimmed, @"^[a-zA-Z0-9_\-\.]+$"))
        {
            throw new InvalidOperationException($"Security Violation: Executable name '{executable}' contains prohibited special characters.");
        }
    }
}
