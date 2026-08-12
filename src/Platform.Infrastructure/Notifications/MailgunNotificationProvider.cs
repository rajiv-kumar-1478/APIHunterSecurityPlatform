using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Notifications;

/// <summary>
/// Mailgun notification provider.
/// Region configurable: MAILGUN_REGION=us (default) | eu
/// US endpoint: https://api.mailgun.net
/// EU endpoint: https://api.eu.mailgun.net
/// </summary>
public class MailgunNotificationProvider(
    IOptions<MailgunOptions> options,
    IHttpClientFactory httpClientFactory,
    ILogger<MailgunNotificationProvider> logger) : INotificationProvider
{
    private readonly MailgunOptions _opts = options.Value;

    public NotificationChannel Channel => NotificationChannel.Email;
    public string ProviderName => "Mailgun";

    public async Task SendAsync(Notification notification, CancellationToken cancellationToken = default)
    {
        var client = CreateClient();

        var content = new MultipartFormDataContent
        {
            { new StringContent(_opts.From), "from" },
            { new StringContent(notification.RecipientEmail), "to" },
            { new StringContent(notification.Subject), "subject" }
        };

        if (notification.IsHtml)
            content.Add(new StringContent(notification.Body), "html");
        else
            content.Add(new StringContent(notification.Body), "text");

        var url = $"{_opts.BaseUrl}/v3/{_opts.Domain}/messages";
        var response = await client.PostAsync(url, content, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            logger.LogError("Mailgun send failed: {Status} {Body}", response.StatusCode, body);
            throw new InvalidOperationException($"Mailgun returned {response.StatusCode}: {body}");
        }

        logger.LogInformation("Mailgun: Sent '{Subject}' to {Recipient}", notification.Subject, notification.RecipientEmail);
    }

    public async Task<ProviderHealthResult> HealthCheckAsync(CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var client = CreateClient();
            // List domains endpoint — lightweight check, validates API key and domain access
            var url = $"{_opts.BaseUrl}/v3/domains/{_opts.Domain}";
            var response = await client.GetAsync(url, cancellationToken);
            sw.Stop();

            if (response.IsSuccessStatusCode)
                return new ProviderHealthResult("Mailgun", true, "Healthy", $"Region: {_opts.Region.ToUpper()}", sw.Elapsed);

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            return new ProviderHealthResult("Mailgun", false, "Unhealthy", $"HTTP {response.StatusCode}: {body}", sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            logger.LogWarning(ex, "Mailgun health check failed");
            return new ProviderHealthResult("Mailgun", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }

    private HttpClient CreateClient()
    {
        var client = httpClientFactory.CreateClient("Mailgun");
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"api:{_opts.ApiKey}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        return client;
    }
}
