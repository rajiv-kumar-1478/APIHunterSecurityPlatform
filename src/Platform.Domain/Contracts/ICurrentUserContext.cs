namespace Platform.Domain.Contracts;

/// <summary>
/// Abstracts the current authenticated user from the HTTP context.
/// Allows application services to access caller identity without a dependency on ASP.NET.
/// </summary>
public interface ICurrentUserContext
{
    Guid? UserId { get; }
    string? SessionId { get; }
    bool IsAuthenticated { get; }
    bool IsPlatformAdmin { get; }
    string CorrelationId { get; }
    string IpAddress { get; }
}
