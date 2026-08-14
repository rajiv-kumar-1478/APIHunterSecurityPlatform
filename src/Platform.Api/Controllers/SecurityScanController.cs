using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
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

    public SecurityScanController(
        ScanJobService scanJobService,
        ScanToolRegistryService toolRegistryService,
        IScanToolHealthService toolHealthService,
        IScanProviderSecretStore secretStore)
    {
        _scanJobService = scanJobService;
        _toolRegistryService = toolRegistryService;
        _toolHealthService = toolHealthService;
        _secretStore = secretStore;
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
        var job = await _scanJobService.GetJobDetailAsync(id, ct);
        if (job == null)
        {
            return NotFound(new { message = $"Scan job '{id}' not found." });
        }

        return Ok(job);
    }

    [HttpGet("jobs/{id:guid}/receipt")]
    public async Task<ActionResult<ScanExecutionReceipt>> GetJobReceipt(Guid id, CancellationToken ct)
    {
        var receipt = await _scanJobService.GetJobReceiptAsync(id, ct);
        if (receipt == null)
        {
            return NotFound(new { message = $"Execution receipt for scan job '{id}' not found or scan not completed." });
        }

        return Ok(receipt);
    }

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
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
}

public record CancelScanJobApiRequest(string Reason, int ExpectedVersion);
