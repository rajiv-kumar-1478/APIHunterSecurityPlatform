using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/security/campaigns")]
[Authorize]
public class ScanCampaignsController : ControllerBase
{
    private readonly IScanCampaignService _campaignService;
    private readonly ICampaignObservabilityService _observabilityService;
    private readonly ICurrentUserContext _currentUser;

    public ScanCampaignsController(
        IScanCampaignService campaignService,
        ICampaignObservabilityService observabilityService,
        ICurrentUserContext currentUser)
    {
        _campaignService = campaignService ?? throw new ArgumentNullException(nameof(campaignService));
        _observabilityService = observabilityService ?? throw new ArgumentNullException(nameof(observabilityService));
        _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
    }

    [HttpGet("health")]
    public async Task<ActionResult<CampaignOperationalHealthDto>> GetHealth(CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var health = await _observabilityService.GetTenantHealthAsync(tenantId, ct);
        return Ok(health);
    }

    [HttpGet("metrics")]
    public async Task<ActionResult<CampaignWindowMetricsDto>> GetMetrics(
        [FromQuery] string window = "24h",
        CancellationToken ct = default)
    {
        var tenantId = ResolveTenantId();
        var timeSpan = window.ToLowerInvariant() switch
        {
            "7d" => TimeSpan.FromDays(7),
            "30d" => TimeSpan.FromDays(30),
            _ => TimeSpan.FromHours(24)
        };

        var metrics = await _observabilityService.GetTenantWindowMetricsAsync(tenantId, timeSpan, ct);
        return Ok(metrics);
    }

    [HttpGet("{id:guid}/history")]
    public async Task<ActionResult<IReadOnlyList<CampaignExecutionHistoryEntryDto>>> GetExecutionHistory(
        Guid id,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] DateTime? sinceUtc = null,
        [FromQuery] SchedulerDecision? decision = null,
        CancellationToken ct = default)
    {
        var tenantId = ResolveTenantId();
        var history = await _observabilityService.GetCampaignExecutionHistoryAsync(
            tenantId, id, page, pageSize, sinceUtc, decision, ct);
        return Ok(history);
    }

    [HttpGet("{id:guid}/diagnostics")]
    public async Task<ActionResult<CampaignDiagnosticsDto>> GetDiagnostics(Guid id, CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var diagnostics = await _observabilityService.GetCampaignDiagnosticsAsync(tenantId, id, ct);

        if (diagnostics == null)
        {
            return NotFound(new { message = $"ScanCampaign '{id}' was not found for current tenant." });
        }

        return Ok(diagnostics);
    }

    [HttpPost]
    public async Task<ActionResult<ScanCampaignDto>> CreateCampaign(
        [FromBody] CreateCampaignRequest request,
        CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var userId = _currentUser.UserId ?? Guid.Empty;

        try
        {
            var campaign = await _campaignService.CreateCampaignAsync(tenantId, userId, request, ct);
            return CreatedAtAction(nameof(GetCampaign), new { id = campaign.Id }, campaign);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ScanCampaignDto>>> ListCampaigns(
        [FromQuery] Guid? repositoryId = null,
        [FromQuery] CampaignStatus? status = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        var tenantId = ResolveTenantId();
        var campaigns = await _campaignService.ListCampaignsAsync(tenantId, repositoryId, status, page, pageSize, ct);
        return Ok(campaigns);
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<ScanCampaignDto>> GetCampaign(Guid id, CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var campaign = await _campaignService.GetCampaignByIdAsync(tenantId, id, ct);

        if (campaign == null)
        {
            return NotFound(new { message = $"ScanCampaign '{id}' was not found for current tenant." });
        }

        return Ok(campaign);
    }

    [HttpPut("{id:guid}")]
    public async Task<ActionResult<ScanCampaignDto>> UpdateCampaign(
        Guid id,
        [FromBody] UpdateCampaignRequest request,
        CancellationToken ct)
    {
        var tenantId = ResolveTenantId();

        try
        {
            var updated = await _campaignService.UpdateCampaignAsync(tenantId, id, request, ct);
            return Ok(updated);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("{id:guid}/pause")]
    public async Task<ActionResult<ScanCampaignDto>> PauseCampaign(
        Guid id,
        [FromQuery] string? reason = null,
        CancellationToken ct = default)
    {
        var tenantId = ResolveTenantId();

        try
        {
            var paused = await _campaignService.PauseCampaignAsync(tenantId, id, reason, ct);
            return Ok(paused);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("{id:guid}/resume")]
    public async Task<ActionResult<ScanCampaignDto>> ResumeCampaign(Guid id, CancellationToken ct)
    {
        var tenantId = ResolveTenantId();

        try
        {
            var resumed = await _campaignService.ResumeCampaignAsync(tenantId, id, ct);
            return Ok(resumed);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("{id:guid}/run-now")]
    public async Task<ActionResult<CampaignRunNowResult>> TriggerRunNow(Guid id, CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var userId = _currentUser.UserId ?? Guid.Empty;

        try
        {
            var result = await _campaignService.TriggerRunNowAsync(tenantId, userId, id, ct);
            return Ok(result);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("{id:guid}/audit-logs")]
    public async Task<ActionResult<IReadOnlyList<CampaignExecutionAuditLogDto>>> GetAuditLogs(
        Guid id,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        var tenantId = ResolveTenantId();
        var logs = await _campaignService.GetAuditLogsAsync(tenantId, id, page, pageSize, ct);
        return Ok(logs);
    }

    [HttpDelete("{id:guid}")]
    public async Task<ActionResult<ScanCampaignDto>> ArchiveCampaign(Guid id, CancellationToken ct)
    {
        var tenantId = ResolveTenantId();

        try
        {
            var archived = await _campaignService.ArchiveCampaignAsync(tenantId, id, ct);
            return Ok(archived);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
    }

    private Guid ResolveTenantId()
    {
        // Authenticated context is the authoritative tenant source.
        // Only Platform Admins may impersonate another tenant via the X-Tenant-ID header.
        if (_currentUser.IsPlatformAdmin &&
            Request.Headers.TryGetValue("X-Tenant-ID", out var tenantHeader) &&
            Guid.TryParse(tenantHeader.ToString(), out var headerTenantId))
        {
            return headerTenantId;
        }

        return _currentUser.UserId ?? Guid.Empty;
    }
}
