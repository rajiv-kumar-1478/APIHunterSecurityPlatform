using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Platform.Api.Controllers;

/// <summary>
/// Requires the caller to be authenticated. Returns 401 (not redirect) for APIs.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequireAuthAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (context.HttpContext.User?.Identity?.IsAuthenticated != true)
        {
            context.Result = new UnauthorizedObjectResult(new
            {
                title = "Authentication required.",
                code = "UNAUTHENTICATED"
            });
        }
    }
}

/// <summary>
/// Requires the caller to be a Platform Admin. Returns 403 for non-admins.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequireAdminAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (context.HttpContext.User?.Identity?.IsAuthenticated != true)
        {
            context.Result = new UnauthorizedObjectResult(new { title = "Authentication required.", code = "UNAUTHENTICATED" });
            return;
        }

        if (!context.HttpContext.User.HasClaim("platform_admin", "true"))
        {
            context.Result = new ObjectResult(new { title = "Admin access required.", code = "FORBIDDEN" })
            {
                StatusCode = 403
            };
        }
    }
}
