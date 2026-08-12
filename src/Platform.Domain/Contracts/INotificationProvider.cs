using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Domain.Contracts;

/// <summary>
/// Pluggable notification provider adapter.
/// Application layer only knows INotificationService — never calls providers directly.
/// </summary>
public interface INotificationProvider
{
    NotificationChannel Channel { get; }
    string ProviderName { get; }

    /// <summary>
    /// Sends a notification. Throws on unrecoverable failure.
    /// </summary>
    Task SendAsync(Notification notification, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a real but controlled health check of the provider.
    /// Does not send user-visible messages.
    /// </summary>
    Task<ProviderHealthResult> HealthCheckAsync(CancellationToken cancellationToken = default);
}
