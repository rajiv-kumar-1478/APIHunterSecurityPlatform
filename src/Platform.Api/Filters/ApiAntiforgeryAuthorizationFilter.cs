using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Platform.Api.Filters;

/// <summary>
/// Validates antiforgery tokens for every unsafe MVC request and emits a stable API error contract.
/// Login remains protected because anonymous access does not bypass request-forgery validation.
/// </summary>
public sealed class ApiAntiforgeryAuthorizationFilter(IAntiforgery antiforgery)
    : IAsyncAuthorizationFilter, IOrderedFilter
{
    public int Order => 1000;

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var method = context.HttpContext.Request.Method;
        if (HttpMethods.IsGet(method) ||
            HttpMethods.IsHead(method) ||
            HttpMethods.IsOptions(method) ||
            HttpMethods.IsTrace(method))
        {
            return;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            context.Result = new BadRequestObjectResult(new
            {
                title = "Invalid or missing anti-forgery token.",
                code = "INVALID_CSRF_TOKEN"
            });
        }
    }
}
