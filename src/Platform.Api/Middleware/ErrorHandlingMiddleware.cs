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
            logger.LogError(ex, "Unhandled exception of type {Type}. CorrelationId: {CorrelationId}", ex.GetType().FullName, correlationId);

            if (ex is Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException || ex.InnerException is Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";

                var csrfResponse = new
                {
                    title = "Invalid or missing anti-forgery token.",
                    code = "INVALID_CSRF_TOKEN",
                    correlationId
                };

                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(csrfResponse,
                        new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
                return;
            }

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
