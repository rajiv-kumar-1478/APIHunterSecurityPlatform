using Platform.Domain.Contracts;

namespace Platform.UnitTests;

internal sealed class TestTenantContext : ITenantContext
{
    internal static Guid DefaultTenantId { get; } =
        Guid.Parse("8bb7f045-9568-4c73-8bc6-b4f893e68524");

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
