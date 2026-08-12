using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Platform.Domain.Contracts;
using Platform.Infrastructure.Persistence;

namespace Platform.Infrastructure.Health;

public class PostgresHealthComponent(PlatformDbContext db) : IHealthComponent
{
    public string ComponentName => "PostgreSQL";

    public async Task<ComponentHealthResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // Lightweight connectivity check
            await db.Database.ExecuteSqlRawAsync("SELECT 1", cancellationToken);
            sw.Stop();
            return new ComponentHealthResult("PostgreSQL", true, "Healthy", null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new ComponentHealthResult("PostgreSQL", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }
}

public class ApiHealthComponent : IHealthComponent
{
    public string ComponentName => "API";

    public Task<ComponentHealthResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new ComponentHealthResult("API", true, "Healthy", $"Version: {GetVersion()}", TimeSpan.Zero));
    }

    private static string GetVersion() =>
        System.Reflection.Assembly.GetEntryAssembly()
            ?.GetName().Version?.ToString() ?? "unknown";
}
