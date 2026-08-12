using Platform.Domain.ValueObjects;

namespace Platform.Domain.Contracts;

/// <summary>
/// The ONLY notification interface the application layer uses.
/// Provider selection is an infrastructure concern.
/// 
/// Usage: await notificationService.SendAsync(notification);
/// </summary>
public interface INotificationService
{
    Task SendAsync(Notification notification, CancellationToken cancellationToken = default);
    Task SendTestAsync(string recipientEmail, CancellationToken cancellationToken = default);
}
