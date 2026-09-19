using Platform.Domain.Contracts;

namespace Platform.IntegrationTests;

internal sealed class TestTenantContext : ITenantContext
{
    internal static Guid DefaultTenantId { get; } =
        Guid.Parse("f8a6fe6d-3ac4-43e8-a1a6-5b36fe006194");

    internal TestTenantContext()
        : this(DefaultTenantId)
    {
    }

    internal TestTenantContext(Guid tenantId)
    {
        TenantId = tenantId;
    }

    public Guid TenantId { get; }
}
