using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Platform.Infrastructure.Persistence;

namespace Platform.Api.Extensions;

public static class HealthProbesExtensions
{
    private static readonly DateTime ProcessStartTimeUtc = DateTime.UtcNow;

    public static IEndpointRouteBuilder MapPlatformHealthProbes(this IEndpointRouteBuilder endpoints)
    {
        // 1. Liveness Probe (/health/live) - lightweight, process-level responsiveness
        endpoints.MapGet("/health/live", () =>
        {
            var uptime = (DateTime.UtcNow - ProcessStartTimeUtc).TotalSeconds;
            return Results.Ok(new
            {
                status = "Live",
                uptimeSeconds = (long)uptime,
                timestampUtc = DateTime.UtcNow
            });
        }).AllowAnonymous();

        // 2. Readiness Probe (/health/ready) - dependencies ready to accept traffic
        endpoints.MapGet("/health/ready", async (PlatformDbContext dbContext, CancellationToken ct) =>
        {
            try
            {
                var dbCanConnect = await dbContext.Database.CanConnectAsync(ct);
                if (!dbCanConnect)
                {
                    return Results.Json(new
                    {
                        status = "NotReady",
                        reason = "Database connectivity check failed.",
                        timestampUtc = DateTime.UtcNow
                    }, statusCode: StatusCodes.Status503ServiceUnavailable);
                }

                return Results.Ok(new
                {
                    status = "Ready",
                    database = "Connected",
                    timestampUtc = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return Results.Json(new
                {
                    status = "NotReady",
                    reason = ex.Message,
                    timestampUtc = DateTime.UtcNow
                }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        }).AllowAnonymous();

        return endpoints;
    }
}
