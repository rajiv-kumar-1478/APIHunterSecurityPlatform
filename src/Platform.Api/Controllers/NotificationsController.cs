using Microsoft.AspNetCore.Mvc;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/notifications")]
[RequireAdmin]
public class NotificationsController(
    IEnumerable<INotificationProvider> providers,
    INotificationService notificationService,
    ICurrentUserContext currentUser) : ControllerBase
{
    [HttpGet("providers")]
    public async Task<IActionResult> GetProviderStatus(CancellationToken ct)
    {
        var results = new List<object>();

        foreach (var provider in providers.Where(p => p.Channel == NotificationChannel.Email))
        {
            var health = await provider.HealthCheckAsync(ct);
            results.Add(new
            {
                name = provider.ProviderName,
                channel = provider.Channel.ToString(),
                isHealthy = health.IsHealthy,
                status = health.Status,
                detail = health.Detail,
                latencyMs = health.Latency?.TotalMilliseconds
            });
        }

        return Ok(results);
    }

    [HttpPost("test")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendTestNotification([FromBody] TestNotificationRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RecipientEmail))
            return BadRequest(new { title = "RecipientEmail is required." });

        try
        {
            await notificationService.SendTestAsync(request.RecipientEmail, ct);
            return Ok(new { message = $"Test notification sent to {request.RecipientEmail}" });
        }
        catch (Exception ex)
        {
            return BadRequest(new { title = "Failed to send test notification.", detail = ex.Message });
        }
    }
}

public record TestNotificationRequest(string RecipientEmail);
