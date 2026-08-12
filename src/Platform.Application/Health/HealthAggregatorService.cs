using Platform.Domain.Contracts;
using Microsoft.Extensions.Logging;

namespace Platform.Application.Health;

public record PlatformHealthReport(
    bool IsHealthy,
    string OverallStatus,
    IReadOnlyList<ComponentHealthResult> Components,
    DateTime CheckedAtUtc);

public class HealthAggregatorService(
    IEnumerable<IHealthComponent> components,
    ILogger<HealthAggregatorService> logger)
{
    public async Task<PlatformHealthReport> CheckAllAsync(CancellationToken ct = default)
    {
        var results = new List<ComponentHealthResult>();

        await Parallel.ForEachAsync(components, ct, async (component, token) =>
        {
            try
            {
                var result = await component.CheckAsync(token);
                lock (results) results.Add(result);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Health check failed for {Component}", component.ComponentName);
                lock (results) results.Add(new ComponentHealthResult(
                    component.ComponentName, false, "Error", ex.Message));
            }
        });

        var isHealthy = results.All(r => r.IsHealthy);
        var status = isHealthy ? "Healthy" : results.Any(r => !r.IsHealthy) ? "Degraded" : "Unhealthy";

        return new PlatformHealthReport(isHealthy, status, results.AsReadOnly(), DateTime.UtcNow);
    }

    public async Task<ComponentHealthResult> CheckSingleAsync(string componentName, CancellationToken ct = default)
    {
        var component = components.FirstOrDefault(c =>
            string.Equals(c.ComponentName, componentName, StringComparison.OrdinalIgnoreCase));

        if (component is null)
            return new ComponentHealthResult(componentName, false, "Not Found", "Component not registered");

        return await component.CheckAsync(ct);
    }
}
