using Platform.Infrastructure.Authentication;

namespace Platform.Api.Middleware;

/// <summary>
/// Injects a correlation ID into every request.
/// If X-Correlation-ID header is present, uses it. Otherwise generates a new one.
/// Correlation ID flows through all log scopes, audit events, and worker jobs.
/// </summary>
public class CorrelationIdMiddleware(RequestDelegate next)
{
    private const string HeaderName = "X-Correlation-ID";

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers[HeaderName].FirstOrDefault()
                         ?? Guid.NewGuid().ToString("N");

        context.Items[CorrelationIdMiddlewareKeys.CorrelationIdKey] = correlationId;
        context.Response.Headers[HeaderName] = correlationId;

        using (Serilog.Context.LogContext.PushProperty("CorrelationId", correlationId))
        {
            await next(context);
        }
    }
}
