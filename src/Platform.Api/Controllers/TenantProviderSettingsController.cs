using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Infrastructure.Security;

namespace Platform.Api.Controllers;

public sealed record AzureOpenAiConfigRequest(
    string ResourceEndpointUrl,
    string? ApiVersion,
    bool IsEnabled = true);

public sealed record AzureOpenAiConfigDto(
    string ProviderName,
    string ResourceEndpointUrl,
    string ApiVersion,
    bool IsEnabled,
    DateTime? UpdatedAtUtc);

[ApiController]
[Route("api/v1/settings/providers")]
public class TenantProviderSettingsController : ControllerBase
{
    private const string AzureOpenAiProvider = "AzureOpenAI";

    private static readonly Regex AzureOpenAiDomainRegex = new(
        @"^[a-zA-Z0-9-]+\.openai\.azure\.(com|us)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IPlatformDbContext _dbContext;
    private readonly ITenantContext _tenantContext;
    private readonly SsrfProtectionService _ssrfProtectionService;

    public TenantProviderSettingsController(
        IPlatformDbContext dbContext,
        ITenantContext tenantContext,
        SsrfProtectionService ssrfProtectionService)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
        _ssrfProtectionService = ssrfProtectionService ?? throw new ArgumentNullException(nameof(ssrfProtectionService));
    }

    [HttpGet("azure-openai")]
    public async Task<IActionResult> GetAzureOpenAiConfig(CancellationToken ct)
    {
        var setting = await _dbContext.TenantProviderSettings
            .AsNoTracking()
            .FirstOrDefaultAsync(
                s => s.TenantId == _tenantContext.TenantId && s.ProviderName == AzureOpenAiProvider,
                ct);

        if (setting == null)
        {
            return Ok(new AzureOpenAiConfigDto(AzureOpenAiProvider, string.Empty, "2023-05-15", false, null));
        }

        return Ok(new AzureOpenAiConfigDto(
            setting.ProviderName,
            setting.ResourceEndpointUrl,
            setting.ApiVersion,
            setting.IsEnabled,
            setting.UpdatedAtUtc));
    }

    [HttpPost("azure-openai")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfigureAzureOpenAi(
        [FromBody] AzureOpenAiConfigRequest request,
        CancellationToken ct)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.ResourceEndpointUrl))
        {
            return BadRequest(new { code = "INVALID_ENDPOINT", message = "ResourceEndpointUrl is required." });
        }

        var url = request.ResourceEndpointUrl.Trim();

        // 1. Validate URI format
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new { code = "INVALID_ENDPOINT_SCHEME", message = "Azure OpenAI endpoint must be an absolute HTTPS URL." });
        }

        // 2. Validate domain regex
        if (!AzureOpenAiDomainRegex.IsMatch(uri.Host))
        {
            return BadRequest(new
            {
                code = "UNAUTHORIZED_HOST",
                message = $"Host '{uri.Host}' is invalid. Azure OpenAI endpoints must end with '.openai.azure.com' or '.openai.azure.us'."
            });
        }

        // 3. Perform live DNS & SSRF screening
        var ssrfResult = await _ssrfProtectionService.ValidateUriAsync(uri, ct);
        if (!ssrfResult.IsAllowed)
        {
            return BadRequest(new
            {
                code = "SSRF_BLOCKED",
                message = $"Endpoint '{uri.Host}' rejected by security policy: {ssrfResult.DenialReason}"
            });
        }

        // Normalize base endpoint: https://{host}
        var normalizedBaseUrl = $"{uri.Scheme}://{uri.Host}";
        var apiVersion = string.IsNullOrWhiteSpace(request.ApiVersion) ? "2023-05-15" : request.ApiVersion.Trim();

        var existing = await _dbContext.TenantProviderSettings
            .FirstOrDefaultAsync(
                s => s.TenantId == _tenantContext.TenantId && s.ProviderName == AzureOpenAiProvider,
                ct);

        if (existing == null)
        {
            existing = new TenantProviderSetting
            {
                Id = Guid.NewGuid(),
                TenantId = _tenantContext.TenantId,
                ProviderName = AzureOpenAiProvider,
                ResourceEndpointUrl = normalizedBaseUrl,
                ApiVersion = apiVersion,
                IsEnabled = request.IsEnabled,
                CreatedAtUtc = DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow
            };
            _dbContext.TenantProviderSettings.Add(existing);
        }
        else
        {
            existing.ResourceEndpointUrl = normalizedBaseUrl;
            existing.ApiVersion = apiVersion;
            existing.IsEnabled = request.IsEnabled;
            existing.UpdatedAtUtc = DateTime.UtcNow;
        }

        await _dbContext.SaveChangesAsync(ct);

        return Ok(new AzureOpenAiConfigDto(
            existing.ProviderName,
            existing.ResourceEndpointUrl,
            existing.ApiVersion,
            existing.IsEnabled,
            existing.UpdatedAtUtc));
    }

    [HttpDelete("azure-openai")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteAzureOpenAiConfig(CancellationToken ct)
    {
        var existing = await _dbContext.TenantProviderSettings
            .FirstOrDefaultAsync(
                s => s.TenantId == _tenantContext.TenantId && s.ProviderName == AzureOpenAiProvider,
                ct);

        if (existing == null)
        {
            return NotFound(new { code = "NOT_CONFIGURED", message = "Azure OpenAI configuration not found." });
        }

        _dbContext.TenantProviderSettings.Remove(existing);
        await _dbContext.SaveChangesAsync(ct);

        return NoContent();
    }
}
