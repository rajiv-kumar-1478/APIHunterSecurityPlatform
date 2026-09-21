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
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/security/scans")]
[Authorize]
public class SecurityScanController : ControllerBase
{
    private const string BugHunterUnavailableCode = "BUGHUNTER_CONTRACT_UNAVAILABLE";

    private readonly ScanJobService _scanJobService;
    private readonly ScanToolRegistryService _toolRegistryService;
    private readonly IScanToolHealthService _toolHealthService;
    private readonly IScanProviderSecretStore _secretStore;
    private readonly ScanPostExecutionProcessor _postProcessor;
    private readonly ScanReportBuilderService _reportBuilder;
    private readonly SecurityReportFormatterRegistry _formatterRegistry;
    private readonly Platform.Application.Scanning.Audit.IScanPlanAuditService _auditService;
    private readonly Platform.Application.Scanning.Execution.IScanExecutionEngine _executionEngine;
    private readonly ITenantContext _tenantContext;

    public SecurityScanController(
        ScanJobService scanJobService,
        ScanToolRegistryService toolRegistryService,
        IScanToolHealthService toolHealthService,
        IScanProviderSecretStore secretStore,
        ScanPostExecutionProcessor postProcessor,
        ScanReportBuilderService reportBuilder,
        Platform.Application.Scanning.Audit.IScanPlanAuditService auditService,
        Platform.Application.Scanning.Execution.IScanExecutionEngine executionEngine,
        ITenantContext tenantContext,
        SecurityReportFormatterRegistry? formatterRegistry = null)
    {
        _scanJobService = scanJobService ?? throw new ArgumentNullException(nameof(scanJobService));
        _toolRegistryService = toolRegistryService ?? throw new ArgumentNullException(nameof(toolRegistryService));
        _toolHealthService = toolHealthService ?? throw new ArgumentNullException(nameof(toolHealthService));
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _postProcessor = postProcessor ?? throw new ArgumentNullException(nameof(postProcessor));
        _reportBuilder = reportBuilder ?? throw new ArgumentNullException(nameof(reportBuilder));
        _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
        _executionEngine = executionEngine ?? throw new ArgumentNullException(nameof(executionEngine));
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
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
        var bugHunterCredentials = await _secretStore.GetStatusAsync("bughunter", ct);
        IReadOnlyList<ScanProviderDto> providers =
        [
            new ScanProviderDto(
                ProviderKey: "bughunter",
                DisplayName: "BugHunter Scan Provider",
                Enabled: true,
                SupportedCapabilities:
                [
                    "SubdomainEnumeration",
                    "DnsResolution",
                    "HttpProbing",
                    "UrlCrawling",
                    "VulnerabilityScanning",
                    "AiAssistedHunting",
                    "ReportGeneration"
                ],
                RequiredTools: ["subfinder", "httpx", "bughunter"],
                AvailabilityStatus: "Available",
                UnavailableReason: null,
                CredentialsConfigured: bugHunterCredentials.Configured)
        ];

        return Ok(providers);
    }

    [HttpGet("jobs")]
    public async Task<ActionResult<IReadOnlyList<ScanJobDetailDto>>> ListJobs(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] SecurityScanJobStatus? status = null,
        CancellationToken ct = default)
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
    public async Task<ActionResult<ScanDiff>> GetJobDiff(
        Guid id,
        [FromQuery] Guid? baselineJobId = null,
        CancellationToken ct = default)
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
    public async Task<IActionResult> GetReport(
        Guid id,
        [FromQuery] string format = "json",
        [FromQuery] Guid? baselineJobId = null,
        CancellationToken ct = default)
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
    public async Task<ActionResult<ScanJobDetailDto>> CreateJob(
        [FromBody] CreateScanJobRequest request,
        CancellationToken ct)
    {
        var admissionFailure = await GetAdmissionFailureAsync(request.ProviderKey, ct);
        if (admissionFailure != null)
        {
            return admissionFailure;
        }

        try
        {
            var job = await _scanJobService.CreateScanJobAsync(request, ct);
            var detail = await _scanJobService.GetJobDetailAsync(job.Id, ct);
            return CreatedAtAction(nameof(GetJob), new { id = job.Id }, detail);
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
    public async Task<ActionResult<ScanJobDetailDto>> RetryJob(Guid id, CancellationToken ct)
    {
        try
        {
            var originalJob = await _scanJobService.GetJobByIdAsync(id, ct);
            if (originalJob == null)
            {
                return NotFound(new { message = $"Scan job '{id}' not found." });
            }

            var admissionFailure = await GetAdmissionFailureAsync(originalJob.ProviderKey, ct);
            if (admissionFailure != null)
            {
                return admissionFailure;
            }

            var job = await _scanJobService.RetryScanJobAsync(id, ct);
            var detail = await _scanJobService.GetJobDetailAsync(job.Id, ct);
            return Ok(detail);
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
    public async Task<ActionResult<ScanJobDetailDto>> CancelJob(
        Guid id,
        [FromBody] CancelScanJobApiRequest request,
        CancellationToken ct)
    {
        try
        {
            var job = await _scanJobService.CancelScanJobAsync(id, request.Reason, request.ExpectedVersion, ct);
            var detail = await _scanJobService.GetJobDetailAsync(job.Id, ct);
            return Ok(detail);
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
    public async Task<ActionResult<Platform.Application.Scanning.Audit.Contracts.ScanProvenanceResponse>> GetProvenance(
        Guid id,
        CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var provenance = await _auditService.GetProvenanceAsync(id, tenantId, ct);
        if (provenance == null)
        {
            return NotFound(new { message = $"Scan provenance for job '{id}' was not found for current tenant." });
        }

        return Ok(provenance);
    }

    [HttpGet("jobs/{id:guid}/invocations")]
    public async Task<ActionResult<Platform.Application.Scanning.Execution.Contracts.ScanJobExecutionSummaryDto>> GetInvocations(
        Guid id,
        CancellationToken ct)
    {
        var tenantId = ResolveTenantId();
        var summary = await _executionEngine.GetExecutionSummaryAsync(id, tenantId, ct);
        if (summary == null)
        {
            return NotFound(new { message = $"Scan tool execution summary for job '{id}' was not found for current tenant." });
        }

        return Ok(summary);
    }

    private async Task<ObjectResult?> GetAdmissionFailureAsync(
        string? providerKey,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            return BadRequest(new
            {
                code = "SCAN_PROVIDER_REQUIRED",
                message = "A registered and enabled scan provider must be selected."
            });
        }

        var runtimeHealth = await _toolHealthService.GetScannerRuntimeHealthAsync(ct);
        var tools = await _toolRegistryService.GetAllToolsAsync(ct);

        if (!runtimeHealth.ReadyForScans && tools.Count == 0)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new
            {
                code = "SCANNER_RUNTIME_UNAVAILABLE",
                message = "Scanner execution is not currently available. Please ensure scanning tools are configured.",
                runtimeStatus = runtimeHealth.Status
            });
        }

        return null;
    }

    private Guid ResolveTenantId() => _tenantContext.TenantId;
}

public record CancelScanJobApiRequest(string Reason, int ExpectedVersion);
