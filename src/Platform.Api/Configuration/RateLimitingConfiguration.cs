using System.Net;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Platform.Domain.Contracts;

namespace Platform.Api.Configuration;

public static class RateLimitingConfiguration
{
    public const string LoginPolicy = "login";
    public const string TenantApiPolicy = "tenant_api";
    public const string AnonymousIpPolicy = "anonymous_ip";
    public const string WebhookIngestionPolicy = "webhook_ingestion";

    public static IServiceCollection AddPlatformRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            // Standard RFC-7807 429 Response with Retry-After header
            options.OnRejected = async (context, token) =>
            {
                context.HttpContext.Response.ContentType = "application/problem+json";

                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
                }
                else
                {
                    context.HttpContext.Response.Headers.RetryAfter = "30";
                }

                var problem = new ProblemDetails
                {
                    Status = StatusCodes.Status429TooManyRequests,
                    Title = "Too Many Requests",
                    Detail = "Rate limit quota exceeded. Please slow down and retry after the specified backoff period.",
                    Instance = context.HttpContext.Request.Path
                };

                await context.HttpContext.Response.WriteAsync(JsonSerializer.Serialize(problem), token);
            };

            // 1. Login / Authentication Policy (Fixed Window: 5 attempts per 15 seconds per IP)
            options.AddPolicy(LoginPolicy, context =>
            {
                var ip = context.Connection.RemoteIpAddress?.ToString() ?? "anon";
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"login_{ip}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromSeconds(15),
                        QueueLimit = 0
                    });
            });

            // 2. Authenticated Tenant API Policy (Token Bucket: Capacity 300, Refill 50/sec)
            options.AddPolicy(TenantApiPolicy, context =>
            {
                var tenantContext = context.RequestServices.GetService<ITenantContext>();
                var partitionKey = tenantContext?.TenantId.ToString() ?? context.Connection.RemoteIpAddress?.ToString() ?? "anon";

                return RateLimitPartition.GetTokenBucketLimiter(
                    partitionKey: $"tenant_{partitionKey}",
                    factory: _ => new TokenBucketRateLimiterOptions
                    {
                        TokenLimit = 300,
                        TokensPerPeriod = 50,
                        ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                        AutoReplenishment = true,
                        QueueLimit = 0
                    });
            });

            // 3. Anonymous IP Policy (Sliding Window: 100 requests per minute)
            options.AddPolicy(AnonymousIpPolicy, context =>
            {
                var ip = context.Connection.RemoteIpAddress?.ToString() ?? "anon";
                return RateLimitPartition.GetSlidingWindowLimiter(
                    partitionKey: $"ip_{ip}",
                    factory: _ => new SlidingWindowRateLimiterOptions
                    {
                        PermitLimit = 100,
                        Window = TimeSpan.FromMinutes(1),
                        SegmentsPerWindow = 6,
                        QueueLimit = 0
                    });
            });

            // 4. CI/CD Webhook Ingestion Policy (Concurrency: 10 concurrent, 60 req/min)
            options.AddPolicy(WebhookIngestionPolicy, context =>
            {
                var appId = context.Request.Headers["X-Application-Id"].ToString();
                var partitionKey = !string.IsNullOrWhiteSpace(appId)
                    ? $"webhook_app_{appId}"
                    : $"webhook_ip_{context.Connection.RemoteIpAddress?.ToString() ?? "anon"}";

                return RateLimitPartition.GetConcurrencyLimiter(
                    partitionKey: partitionKey,
                    factory: _ => new ConcurrencyLimiterOptions
                    {
                        PermitLimit = 10,
                        QueueLimit = 20
                    });
            });
        });

        return services;
    }
}
