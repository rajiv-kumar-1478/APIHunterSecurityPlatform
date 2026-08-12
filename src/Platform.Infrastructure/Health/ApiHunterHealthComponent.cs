using Platform.Domain.Contracts;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Health;

public class ApiHunterHealthComponent(IApiHunterSource source) : IHealthComponent
{
    public string ComponentName => "APIHunterSource";

    public Task<ComponentHealthResult> CheckAsync(CancellationToken ct = default)
    {
        return source.HealthCheckAsync(ct);
    }
}
