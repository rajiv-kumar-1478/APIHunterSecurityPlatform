using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Scanning.Verification;
using Platform.Domain.Contracts;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/applications")]
public class RegisteredApplicationsController : ControllerBase
{
    private readonly IRegisteredApplicationService _applicationService;
    private readonly ITenantContext _tenantContext;

    public RegisteredApplicationsController(
        IRegisteredApplicationService applicationService,
        ITenantContext tenantContext)
    {
        _applicationService = applicationService ?? throw new ArgumentNullException(nameof(applicationService));
        _tenantContext = tenantContext ?? throw new ArgumentNullException(nameof(tenantContext));
    }

    [HttpGet]
    public async Task<IActionResult> GetApplications(CancellationToken ct)
    {
        var applications = await _applicationService.GetApplicationsAsync(_tenantContext.TenantId, ct);
        return Ok(applications);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetApplication(Guid id, CancellationToken ct)
    {
        var application = await _applicationService.GetByIdAsync(_tenantContext.TenantId, id, ct);
        if (application == null)
        {
            return NotFound(new { code = "APPLICATION_NOT_FOUND", message = $"Application '{id}' was not found." });
        }

        return Ok(application);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterApplication([FromBody] RegisterApplicationRequest request, CancellationToken ct)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.ApplicationId))
        {
            return BadRequest(new { code = "INVALID_PAYLOAD", message = "ApplicationId is required." });
        }

        if (string.IsNullOrWhiteSpace(request.AuthorizedTargetUrl))
        {
            return BadRequest(new { code = "INVALID_PAYLOAD", message = "AuthorizedTargetUrl is required." });
        }

        try
        {
            var result = await _applicationService.RegisterApplicationAsync(_tenantContext.TenantId, request, ct);
            return CreatedAtAction(nameof(GetApplication), new { id = result.Application.Id }, result);
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { code = "APPLICATION_ALREADY_EXISTS", message = ex.Message });
        }
    }

    [HttpPost("{id:guid}/regenerate-secret")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegenerateSecret(Guid id, CancellationToken ct)
    {
        try
        {
            var result = await _applicationService.RegenerateSecretAsync(_tenantContext.TenantId, id, ct);
            return Ok(result);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { code = "APPLICATION_NOT_FOUND", message = ex.Message });
        }
    }

    public sealed record ToggleStatusRequest(bool Enabled);

    [HttpPatch("{id:guid}/status")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ToggleStatus(Guid id, [FromBody] ToggleStatusRequest request, CancellationToken ct)
    {
        if (request == null)
        {
            return BadRequest(new { code = "INVALID_PAYLOAD", message = "Enabled status must be specified." });
        }

        try
        {
            var updated = await _applicationService.ToggleStatusAsync(_tenantContext.TenantId, id, request.Enabled, ct);
            return Ok(updated);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { code = "APPLICATION_NOT_FOUND", message = ex.Message });
        }
    }

    [HttpDelete("{id:guid}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteApplication(Guid id, CancellationToken ct)
    {
        var deleted = await _applicationService.DeleteApplicationAsync(_tenantContext.TenantId, id, ct);
        if (!deleted)
        {
            return NotFound(new { code = "APPLICATION_NOT_FOUND", message = $"Application '{id}' was not found." });
        }

        return NoContent();
    }
}
