using Microsoft.AspNetCore.Mvc;
using Platform.Application.Audit;
using Platform.Application.Common;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/audit")]
[RequireAdmin]
public class AuditController(AuditQueryService auditQueryService) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAuditEvents(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] Guid? userId = null,
        [FromQuery] string? eventCode = null,
        [FromQuery] DateTime? fromUtc = null,
        [FromQuery] DateTime? toUtc = null,
        CancellationToken ct = default)
    {
        AuditEventCode? code = null;
        if (!string.IsNullOrWhiteSpace(eventCode) && Enum.TryParse<AuditEventCode>(eventCode, true, out var parsed))
            code = parsed;

        var result = await auditQueryService.GetAuditEventsAsync(
            new PaginationRequest(page, pageSize), userId, code, fromUtc, toUtc, ct);

        return Ok(result);
    }
}
