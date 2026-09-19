using Microsoft.AspNetCore.Authorization;

namespace Platform.Api.Controllers;

/// <summary>
/// Standard authorization-policy alias for authenticated API endpoints.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireAuthAttribute : AuthorizeAttribute;

/// <summary>
/// Standard authorization-policy alias for platform-administrator endpoints.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireAdminAttribute : AuthorizeAttribute
{
    public RequireAdminAttribute()
    {
        Policy = "PlatformAdmin";
    }
}
