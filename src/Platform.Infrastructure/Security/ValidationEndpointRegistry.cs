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
        ["Slack"] = new Uri("https://slack.com"),

        // Phase 5 extension providers. Each origin must match the host literal used by the
        // corresponding validator descriptor, because the SSRF handler pins the socket to the
        // address resolved from this entry while TLS SNI uses the request host.
        ["HuggingFace"] = new Uri("https://huggingface.co"),
        ["Perplexity"] = new Uri("https://api.perplexity.ai"),
        ["Cohere"] = new Uri("https://api.cohere.com"),
        ["FireworksAI"] = new Uri("https://api.fireworks.ai"),
        ["Replicate"] = new Uri("https://api.replicate.com"),
        ["OpenRouter"] = new Uri("https://openrouter.ai"),
        ["XAI"] = new Uri("https://api.x.ai"),
        ["Cerebras"] = new Uri("https://api.cerebras.ai"),
        ["Tavily"] = new Uri("https://api.tavily.com"),
        ["FalAi"] = new Uri("https://rest.alpha.fal.ai"),
        ["JinaAI"] = new Uri("https://api.jina.ai"),
        ["KlingAI"] = new Uri("https://api.klingai.com"),
        ["RunwayML"] = new Uri("https://api.runwayml.com"),
        ["RunPod"] = new Uri("https://api.runpod.io"),
        ["GoogleGemini"] = new Uri("https://generativelanguage.googleapis.com"),
        ["ElevenLabs"] = new Uri("https://api.elevenlabs.io"),
        ["TogetherAI"] = new Uri("https://api.together.xyz"),
        ["Mistral"] = new Uri("https://api.mistral.ai"),
        ["StabilityAI"] = new Uri("https://api.stability.ai"),
        ["AI21"] = new Uri("https://api.ai21.com"),
        ["AssemblyAI"] = new Uri("https://api.assemblyai.com"),
        ["Deepgram"] = new Uri("https://api.deepgram.com"),
        ["LeonardoAI"] = new Uri("https://cloud.leonardo.ai")
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
