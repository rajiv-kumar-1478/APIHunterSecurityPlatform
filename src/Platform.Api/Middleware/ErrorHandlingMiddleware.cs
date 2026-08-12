using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;

namespace Platform.Api.Middleware;

/// <summary>
/// Global error handler. Suppresses stack traces in production.
/// Returns a structured JSON error response with correlation ID.
/// </summary>
public class ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger, IHostEnvironment env)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            var correlationId = context.Items["CorrelationId"]?.ToString() ?? "unknown";
            logger.LogError(ex, "Unhandled exception. CorrelationId: {CorrelationId}", correlationId);

            context.Response.StatusCode = 500;
            context.Response.ContentType = "application/json";

            var response = new
            {
                title = "An unexpected error occurred.",
                correlationId,
                // Only expose detail in development
                detail = env.IsDevelopment() ? ex.Message : null
            };

            await context.Response.WriteAsync(
                JsonSerializer.Serialize(response,
                    new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        }
    }
}
