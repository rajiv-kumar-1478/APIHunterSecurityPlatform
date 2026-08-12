using Microsoft.AspNetCore.Http;
using Platform.Application.Permissions;
using Platform.Domain.Contracts;

namespace Platform.Infrastructure.Authentication;

/// <summary>
/// Implements ICurrentUserContext from the HTTP context.
/// Reads the session-based claims set by the authentication middleware.
/// </summary>
public class HttpCurrentUserContext(IHttpContextAccessor httpContextAccessor) : ICurrentUserContext, ICurrentUserContextProvider
{
    private IHttpContextAccessor _accessor = httpContextAccessor;

    public Guid? UserId
    {
        get
        {
            var claim = _accessor.HttpContext?.User?.FindFirst("sub")?.Value;
            return Guid.TryParse(claim, out var id) ? id : null;
        }
    }

    public string? SessionId =>
        _accessor.HttpContext?.User?.FindFirst("sid")?.Value;

    public bool IsAuthenticated =>
        _accessor.HttpContext?.User?.Identity?.IsAuthenticated ?? false;

    public bool IsPlatformAdmin =>
        _accessor.HttpContext?.User?.HasClaim("platform_admin", "true") ?? false;

    public string CorrelationId =>
        _accessor.HttpContext?.Items[CorrelationIdMiddlewareKeys.CorrelationIdKey]?.ToString()
        ?? _accessor.HttpContext?.Request.Headers["X-Correlation-ID"].ToString()
        ?? Guid.NewGuid().ToString("N");

    public string IpAddress =>
        _accessor.HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "unknown";
}

public static class CorrelationIdMiddlewareKeys
{
    public const string CorrelationIdKey = "CorrelationId";
}
