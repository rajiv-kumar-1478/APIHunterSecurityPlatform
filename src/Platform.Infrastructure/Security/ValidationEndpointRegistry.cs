using System.Collections.Concurrent;

namespace Platform.Infrastructure.Security;

public class ValidationEndpointRegistry
{
    private static readonly ConcurrentDictionary<string, Uri> EndpointRegistry = new(StringComparer.OrdinalIgnoreCase)
    {
        ["OpenAI"] = new Uri("https://api.openai.com"),
        ["Anthropic"] = new Uri("https://api.anthropic.com"),
        ["GitHub"] = new Uri("https://api.github.com"),
        ["AWSIAM"] = new Uri("https://sts.amazonaws.com"),
        ["Stripe"] = new Uri("https://api.stripe.com"),
        ["SendGrid"] = new Uri("https://api.sendgrid.com"),
        ["Mailgun"] = new Uri("https://api.mailgun.net"),
        ["DeepSeek"] = new Uri("https://api.deepseek.com"),
        ["Groq"] = new Uri("https://api.groq.com"),
        ["Slack"] = new Uri("https://slack.com")
    };

    public bool IsProviderSupported(string providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName)) return false;
        return EndpointRegistry.ContainsKey(providerName);
    }

    public Uri GetAllowlistedEndpoint(string providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName))
            throw new ArgumentException("Provider name cannot be empty.", nameof(providerName));

        if (EndpointRegistry.TryGetValue(providerName, out var uri))
        {
            return uri;
        }

        throw new InvalidOperationException($"Provider '{providerName}' is not registered in the server-controlled ValidationEndpointRegistry.");
    }
}
