using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Notifications;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Notifications;

/// <summary>
/// Selects the active email provider based on EMAIL_PROVIDER environment configuration.
/// Application layer never calls this directly — NotificationService does.
/// </summary>
public class ProviderSelector(IOptions<NotificationOptions> options) : IProviderSelector
{
    private readonly string _emailProvider = options.Value.EmailProvider.ToLower();

    public INotificationProvider? SelectEmailProvider(IEnumerable<INotificationProvider> providers)
    {
        var emailProviders = providers
            .Where(p => p.Channel == NotificationChannel.Email)
            .ToList();

        return _emailProvider switch
        {
            "sendgrid" => emailProviders.FirstOrDefault(p => p.ProviderName == "SendGrid"),
            "mailgun"  => emailProviders.FirstOrDefault(p => p.ProviderName == "Mailgun"),
            _          => emailProviders.FirstOrDefault(p => p.ProviderName == "SMTP") // Default: SMTP
        };
    }
}
