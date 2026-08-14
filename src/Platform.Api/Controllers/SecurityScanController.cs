using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Reporting.Formatters;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/security/scans")]
[Authorize]
public class SecurityScanController : ControllerBase
{
    private readonly ScanJobService _scanJobService;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly IScanToolHealthService _toolHealthService;
    private readonly IScanProviderSecretStore _secretStore;
    private readonly ScanPostExecutionProcessor _postProcessor;
    private readonly ScanReportBuilderService _reportBuilder;
    private readonly SecurityReportFormatterRegistry _formatterRegistry;
    private readonly Platform.Application.Scanning.Audit.IScanPlanAuditService _auditService;

    public SecurityScanController(
        ScanJobService scanJobService,
        ScanToolRegistryService toolRegistryService,
        IScanToolHealthService toolHealthService,
        IScanProviderSecretStore secretStore,
        ScanPostExecutionProcessor postProcessor,
        ScanReportBuilderService reportBuilder,
        Platform.Application.Scanning.Audit.IScanPlanAuditService? auditService = null,
        SecurityReportFormatterRegistry? formatterRegistry = null)
    {
        _scanJobService = scanJobService;
        _toolRegistryService = toolRegistryService;
        _toolHealthService = toolHealthService;
        _secretStore = secretStore;
        _postProcessor = postProcessor;
        _reportBuilder = reportBuilder;
        _auditService = auditService!;
        _formatterRegistry = formatterRegistry ?? new SecurityReportFormatterRegistry();
    }

    [HttpGet("capabilities")]
    public async Task<ActionResult<IReadOnlyList<ScanCapabilityDto>>> GetCapabilities(CancellationToken ct)
    {
        var capabilities = await _toolRegistryService.GetCapabilityManifestAsync(ct);
        return Ok(capabilities);
    }

    [HttpGet("tools")]
    public async Task<ActionResult<IReadOnlyList<ScanToolDto>>> GetTools(CancellationToken ct)
    {
        var tools = await _toolHealthService.GetAllToolStatusAsync(ct);
        return Ok(tools);
    }

    [HttpGet("runtime/health")]
    public async Task<ActionResult<ScannerRuntimeHealthDto>> GetRuntimeHealth(CancellationToken ct)
    {
        var health = await _toolHealthService.GetScannerRuntimeHealthAsync(ct);
        return Ok(health);
    }

    [HttpGet("providers")]
    public async Task<ActionResult<IReadOnlyList<ScanProviderDto>>> GetProviders(CancellationToken ct)
    {
        var bughunterSecretStatus = await _secretStore.GetStatusAsync("bughunter", ct);

        var providers = new List<ScanProviderDto>
        {
            new ScanProviderDto(
                ProviderKey: "bughunter",
                DisplayName: "BugHunter AI Scan Provider (Contract Foundation)",
                Enabled: bughunterSecretStatus.Configured,
                SupportedCapabilities: new[] { "SubdomainEnumeration", "DnsResolution", "HttpProbing", "UrlCrawling", "VulnerabilityScanning", "AiAssistedHunting", "ReportGeneration" },
                RequiredTools: new[] { "subfinder", "httpx", "bughunter" }
            )
        };

        return Ok(providers);
    }

    [HttpGet("jobs")]
    public async Task<ActionResult<IReadOnlyList<ScanJobDetailDto>>> ListJobs([FromQuery] int page = 1, [FromQuery] int pageSize = 50, [FromQuery] SecurityScanJobStatus? status = null, CancellationToken ct = default)
    {
        var jobs = await _scanJobService.ListJobsDetailAsync(page, pageSize, status, ct);
        return Ok(jobs);
    }

    [HttpGet("jobs/{id:guid}")]
    public async Task<ActionResult<ScanJobDetailDto>> GetJob(Guid id, CancellationToken ct)
    {
        try
        {
            var job = await _scanJobService.GetJobDetailAsync(id, ct);
            if (job == null)
            {
                return NotFound(new { message = $"Scan job '{id}' not found." });
            }

            return Ok(job);
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
    }

    [HttpGet("jobs/{id:guid}/receipt")]
    public async Task<ActionResult<ScanExecutionReceipt>> GetJobReceipt(Guid id, CancellationToken ct)
    {
        try
        {
            var receipt = await _scanJobService.GetJobReceiptAsync(id, ct);
            if (receipt == null)
            {
                return NotFound(new { message = $"Execution receipt for scan job '{id}' not found or scan not completed." });
            }

            return Ok(receipt);
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
    }

    [HttpGet("jobs/{id:guid}/summary")]
    public async Task<ActionResult<ScanResultSummary>> GetJobSummary(Guid id, CancellationToken ct)
    {
        try
        {
            var summary = await _postProcessor.BuildSummaryAsync(id, ct);
            return Ok(summary);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
    }

    [HttpGet("jobs/{id:guid}/diff")]
    public async Task<ActionResult<ScanDiff>> GetJobDiff(Guid id, [FromQuery] Guid? baselineJobId = null, CancellationToken ct = default)
    {
        try
        {
            var diff = await _postProcessor.CalculateDiffAsync(id, baselineJobId, ct);
            return Ok(diff);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("jobs/{id:guid}/report")]
    public async Task<IActionResult> GetReport(Guid id, [FromQuery] string format = "json", [FromQuery] Guid? baselineJobId = null, CancellationToken ct = default)
    {
        try
        {
            var canonicalReport = await _reportBuilder.BuildCanonicalReportAsync(id, baselineJobId, ct);
            var result = _formatterRegistry.FormatReport(format, canonicalReport);

            return Content(result.Content, result.ContentType, Encoding.UTF8);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge, new { message = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
    }

    [HttpGet("jobs/{id:guid}/report/json")]
    public Task<IActionResult> GetJsonReport(Guid id, [FromQuery] Guid? baselineJobId = null, CancellationToken ct = default)
        => GetReport(id, "json", baselineJobId, ct);

    [HttpGet("jobs/{id:guid}/report/sarif")]
    public Task<IActionResult> GetSarifReport(Guid id, [FromQuery] Guid? baselineJobId = null, CancellationToken ct = default)
        => GetReport(id, "sarif", baselineJobId, ct);

    [HttpGet("jobs/{id:guid}/report/markdown")]
    public Task<IActionResult> GetMarkdownReport(Guid id, [FromQuery] Guid? baselineJobId = null, CancellationToken ct = default)
        => GetReport(id, "markdown", baselineJobId, ct);

    [HttpGet("jobs/{id:guid}/report/html")]
    public Task<IActionResult> GetHtmlReport(Guid id, [FromQuery] Guid? baselineJobId = null, CancellationToken ct = default)
        => GetReport(id, "html", baselineJobId, ct);

    [HttpPost("jobs")]
    public async Task<ActionResult<SecurityScanJob>> CreateJob([FromBody] CreateScanJobRequest request, CancellationToken ct)
    {
        try
        {
            var job = await _scanJobService.CreateScanJobAsync(request, ct);
            return CreatedAtAction(nameof(GetJob), new { id = job.Id }, job);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
    }

    [HttpPost("jobs/{id:guid}/retry")]
    public async Task<ActionResult<SecurityScanJob>> RetryJob(Guid id, CancellationToken ct)
    {
        try
        {
            var job = await _scanJobService.RetryScanJobAsync(id, ct);
            return Ok(job);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("jobs/{id:guid}/cancel")]
    public async Task<ActionResult<SecurityScanJob>> CancelJob(Guid id, [FromBody] CancelScanJobApiRequest request, CancellationToken ct)
    {
        try
        {
            var job = await _scanJobService.CancelScanJobAsync(id, request.Reason, request.ExpectedVersion, ct);
            return Ok(job);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("jobs/{id:guid}/provenance")]
    public async Task<ActionResult<Platform.Application.Scanning.Audit.Contracts.ScanProvenanceResponse>> GetProvenance(Guid id, CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var provenance = await _auditService.GetProvenanceAsync(id, tenantId, ct);
        if (provenance == null)
        {
            return NotFound(new { message = $"Scan provenance for job '{id}' was not found for current tenant." });
        }

        return Ok(provenance);
    }

    private Guid ResolveTenantId()
    {
        if (User.IsInRole("Admin") &&
            Request.Headers.TryGetValue("X-Tenant-ID", out var tenantHeader) &&
            Guid.TryParse(tenantHeader.ToString(), out var headerTenantId))
        {
            return headerTenantId;
        }

        var claim = User.FindFirst("tenant_id")?.Value
            ?? User.FindFirst("TenantId")?.Value
            ?? User.FindFirst(System.Security.Claims.ClaimTypes.GroupSid)?.Value;

        if (Guid.TryParse(claim, out var parsedTenantId))
        {
            return parsedTenantId;
        }

        return Guid.Empty;
    }
}

public record CancelScanJobApiRequest(string Reason, int ExpectedVersion);
