using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Tenancy;

/// <summary>
/// Immutable single-tenant context shared by API and worker hosts.
/// </summary>
public sealed class ConfiguredTenantContext(IOptions<TenantOptions> options) : ITenantContext
{
    public Guid TenantId { get; } = options.Value.Id != Guid.Empty
        ? options.Value.Id
        : throw new OptionsValidationException(
            TenantOptions.SectionName,
            typeof(TenantOptions),
            ["Tenant:Id must be a non-empty GUID."]);
}
