using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Adapters.ApiHunter;

public class ApiHunterStatusMapper : IApiHunterStatusMapper
{
    public PlatformKeyStatus MapStatus(int statusCode) => statusCode switch
    {
        1 => PlatformKeyStatus.Valid,
        7 => PlatformKeyStatus.ValidNoCredits,
        0 => PlatformKeyStatus.Invalid,
        -99 => PlatformKeyStatus.Unverified,
        6 => PlatformKeyStatus.Error,
        _ => PlatformKeyStatus.Unknown
    };

    public string MapApiType(int apiTypeCode) => apiTypeCode switch
    {
        100 => "OpenAI",
        120 => "AnthropicClaude",
        130 => "GoogleAI",
        140 => "Cohere",
        150 => "HuggingFace",
        160 => "StabilityAI",
        180 => "Replicate",
        190 => "TogetherAI",
        198 => "DeepSeek",
        199 => "ElevenLabs",
        207 => "XAI",
        208 => "FireworksAI",
        210 => "KlingAI",
        215 => "PolloAI",
        220 => "RunwayML",
        230 => "A2E",
        240 => "PiAPI",
        250 => "Groq",
        260 => "MistralAI",
        270 => "OpenRouter",
        280 => "Perplexity",
        290 => "Cerebras",
        300 => "VoyageAI",
        310 => "AWSBedrock",
        320 => "AzureOpenAI",
        330 => "AWSIAM",
        350 => "AI21Labs",
        360 => "AssemblyAI",
        370 => "Deepgram",
        380 => "JinaAI",
        400 => "Upstage",
        405 => "LeonardoAI",
        415 => "FalAI",
        420 => "RunPod",
        422 => "Tavily",
        410 => "SendGrid",
        425 => "Mailgun",
        430 => "Slack",
        440 => "Facebook",
        450 => "GoogleOAuth",
        460 => "Stripe",
        470 => "TikTok",
        480 => "GcpHmac",
        490 => "GitHubToken",
        500 => "ServerCredential",
        600 => "Mapbox",
        610 => "WeatherApi",
        _ => $"UnknownType_{apiTypeCode}"
    };
}
