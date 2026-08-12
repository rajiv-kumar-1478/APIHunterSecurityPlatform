using Platform.Domain.Contracts;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace Platform.Application.Notifications;

/// <summary>
/// Application-facing notification service.
/// Only knows INotificationProvider — provider selection is infrastructure concern.
/// 
/// Usage: await notificationService.SendAsync(notification);
/// </summary>
public class NotificationService(
    IEnumerable<INotificationProvider> providers,
    IProviderSelector providerSelector,
    ILogger<NotificationService> logger) : INotificationService
{
    public async Task SendAsync(Notification notification, CancellationToken cancellationToken = default)
    {
        var provider = providerSelector.SelectEmailProvider(providers);
        if (provider is null)
        {
            logger.LogWarning("No email provider configured. Notification '{Subject}' not sent.", notification.Subject);
            return;
        }

        try
        {
            await provider.SendAsync(notification, cancellationToken);
            logger.LogInformation("Notification '{Subject}' sent via {Provider}", notification.Subject, provider.ProviderName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send notification '{Subject}' via {Provider}", notification.Subject, provider.ProviderName);
            throw;
        }
    }

    public async Task SendTestAsync(string recipientEmail, CancellationToken cancellationToken = default)
    {
        var testNotification = new Notification(
            Subject: "APIHunter Platform — Test Notification",
            Body: "<h2>✅ Test Email</h2><p>Your notification provider is configured correctly.</p>",
            RecipientEmail: recipientEmail,
            IsHtml: true);

        await SendAsync(testNotification, cancellationToken);
    }
}

/// <summary>
/// Selects the active email provider based on configuration/priority.
/// </summary>
public interface IProviderSelector
{
    INotificationProvider? SelectEmailProvider(IEnumerable<INotificationProvider> providers);
}
