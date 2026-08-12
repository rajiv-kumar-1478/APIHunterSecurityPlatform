using System.Diagnostics;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using Platform.Application.Configuration;
using Platform.Application.Notifications;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Notifications;

public class SmtpNotificationProvider(
    IOptions<SmtpOptions> options,
    ILogger<SmtpNotificationProvider> logger) : INotificationProvider
{
    private readonly SmtpOptions _opts = options.Value;

    public NotificationChannel Channel => NotificationChannel.Email;
    public string ProviderName => "SMTP";

    public async Task SendAsync(Notification notification, CancellationToken cancellationToken = default)
    {
        var message = BuildMessage(notification);
        using var client = new SmtpClient();

        await client.ConnectAsync(_opts.Host, _opts.Port,
            _opts.UseTls ? SecureSocketOptions.StartTls : SecureSocketOptions.None,
            cancellationToken);

        if (!string.IsNullOrWhiteSpace(_opts.Username))
            await client.AuthenticateAsync(_opts.Username, _opts.Password, cancellationToken);

        await client.SendAsync(message, cancellationToken);
        await client.DisconnectAsync(true, cancellationToken);

        logger.LogInformation("SMTP: Sent '{Subject}' to {Recipient}", notification.Subject, notification.RecipientEmail);
    }

    public async Task<ProviderHealthResult> HealthCheckAsync(CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var client = new SmtpClient();
            await client.ConnectAsync(_opts.Host, _opts.Port,
                _opts.UseTls ? SecureSocketOptions.StartTls : SecureSocketOptions.None,
                cancellationToken);

            if (!string.IsNullOrWhiteSpace(_opts.Username))
                await client.AuthenticateAsync(_opts.Username, _opts.Password, cancellationToken);

            await client.DisconnectAsync(true, cancellationToken);
            sw.Stop();

            return new ProviderHealthResult("SMTP", true, "Healthy", null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            logger.LogWarning(ex, "SMTP health check failed");
            return new ProviderHealthResult("SMTP", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }

    private MimeMessage BuildMessage(Notification notification)
    {
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(_opts.From));
        message.To.Add(notification.RecipientName is not null
            ? new MailboxAddress(notification.RecipientName, notification.RecipientEmail)
            : MailboxAddress.Parse(notification.RecipientEmail));
        message.Subject = notification.Subject;

        var builder = new BodyBuilder();
        if (notification.IsHtml) builder.HtmlBody = notification.Body;
        else builder.TextBody = notification.Body;
        message.Body = builder.ToMessageBody();

        return message;
    }
}
