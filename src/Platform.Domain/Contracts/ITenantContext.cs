namespace Platform.Domain.Contracts;

/// <summary>
/// Provides the single configured tenant boundary for the running host.
/// Tenant identity is deployment configuration, never a user, request header, or claim fallback.
/// </summary>
public interface ITenantContext
{
    Guid TenantId { get; }
}
