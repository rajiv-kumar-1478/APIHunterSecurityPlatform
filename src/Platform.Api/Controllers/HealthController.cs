using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Health;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/health")]
public class HealthController(HealthAggregatorService healthService) : ControllerBase
{
    /// <summary>Process liveness only; it does not claim dependency readiness.</summary>
    [AllowAnonymous]
    [HttpGet]
    [HttpGet("live")]
    public IActionResult GetHealth()
    {
        return Ok(new { status = "Alive", timestamp = DateTime.UtcNow });
    }

    /// <summary>Public, non-sensitive readiness check for container orchestration.</summary>
    [AllowAnonymous]
    [HttpGet("ready")]
    public async Task<IActionResult> GetReadiness(CancellationToken ct)
    {
        var database = await healthService.CheckSingleAsync("PostgreSQL", ct);
        return StatusCode(database.IsHealthy ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable, new
        {
            status = database.IsHealthy ? "Ready" : "NotReady",
            ready = database.IsHealthy,
            checkedAt = DateTime.UtcNow
        });
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
