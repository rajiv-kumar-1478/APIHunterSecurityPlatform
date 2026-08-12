using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Notifications;

public class SendGridNotificationProvider(
    IOptions<SendGridOptions> options,
    ILogger<SendGridNotificationProvider> logger) : INotificationProvider
{
    private readonly SendGridOptions _opts = options.Value;

    public NotificationChannel Channel => NotificationChannel.Email;
    public string ProviderName => "SendGrid";

    public async Task SendAsync(Notification notification, CancellationToken cancellationToken = default)
    {
        var client = new SendGridClient(_opts.ApiKey);
        var from = new EmailAddress(_opts.From);
        var to = new EmailAddress(notification.RecipientEmail, notification.RecipientName);

        var msg = notification.IsHtml
            ? MailHelper.CreateSingleEmail(from, to, notification.Subject, null, notification.Body)
            : MailHelper.CreateSingleEmail(from, to, notification.Subject, notification.Body, null);

        var response = await client.SendEmailAsync(msg, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Body.ReadAsStringAsync(cancellationToken);
            logger.LogError("SendGrid send failed: {Status} {Body}", response.StatusCode, body);
            throw new InvalidOperationException($"SendGrid returned {response.StatusCode}: {body}");
        }

        logger.LogInformation("SendGrid: Sent '{Subject}' to {Recipient}", notification.Subject, notification.RecipientEmail);
    }

    public async Task<ProviderHealthResult> HealthCheckAsync(CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // Check API key validity via stats endpoint (lightweight, no email sent)
            var client = new SendGridClient(_opts.ApiKey);
            var response = await client.RequestAsync(
                method: SendGridClient.Method.GET,
                urlPath: "scopes",
                cancellationToken: cancellationToken);

            sw.Stop();

            if (response.IsSuccessStatusCode)
                return new ProviderHealthResult("SendGrid", true, "Healthy", null, sw.Elapsed);

            var body = await response.Body.ReadAsStringAsync(cancellationToken);
            return new ProviderHealthResult("SendGrid", false, "Unhealthy", $"HTTP {response.StatusCode}: {body}", sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            logger.LogWarning(ex, "SendGrid health check failed");
            return new ProviderHealthResult("SendGrid", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }
}
