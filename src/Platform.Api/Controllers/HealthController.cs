using Microsoft.AspNetCore.Mvc;
using Platform.Application.Health;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/health")]
public class HealthController(HealthAggregatorService healthService) : ControllerBase
{
    /// <summary>Public — used by Render/Docker health probes.</summary>
    [HttpGet]
    public IActionResult GetHealth()
    {
        return Ok(new { status = "Healthy", timestamp = DateTime.UtcNow });
    }

    /// <summary>Admin only — full component breakdown.</summary>
    [HttpGet("detailed")]
    [RequireAdmin]
    public async Task<IActionResult> GetDetailedHealth(CancellationToken ct)
    {
        var report = await healthService.CheckAllAsync(ct);
        var statusCode = report.IsHealthy ? 200 : 503;

        return StatusCode(statusCode, new
        {
            status = report.OverallStatus,
            isHealthy = report.IsHealthy,
            checkedAt = report.CheckedAtUtc,
            components = report.Components.Select(c => new
            {
                name = c.ComponentName,
                isHealthy = c.IsHealthy,
                status = c.Status,
                detail = c.Detail,
                latencyMs = c.Latency?.TotalMilliseconds
            })
        });
    }
}
