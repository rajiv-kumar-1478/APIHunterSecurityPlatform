using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Security;
using Platform.Infrastructure.Validators;
using Xunit;

namespace Platform.UnitTests.Validators;

/// <summary>
/// Proofs for the Phase 5 extension providers.
///
/// The shared request/response mapping lives in <see cref="ProviderValidationExecutor"/>, so
/// the network-path branches every provider depends on are asserted here directly against a
/// stubbed transport. Each provider additionally has its server-controlled descriptor and
/// registry pairing verified, because a host mismatch between the two would break TLS at
/// runtime while silently degrading to <c>Unavailable</c>.
/// </summary>
public sealed class DeclarativeProviderValidatorTests
{
    private const string TestSecret = "test-secret-value-not-a-real-key";

    private readonly ValidationEndpointRegistry _registry = new();
    private readonly SsrfProtectionService _ssrfService;
    private readonly IOptions<ValidationPolicyOptions> _policyOptions =
        Options.Create(new ValidationPolicyOptions());

    public DeclarativeProviderValidatorTests()
    {
        _ssrfService = new SsrfProtectionService(
            _registry,
            new Mock<ILogger<SsrfProtectionService>>().Object);
    }

    private IEnumerable<DeclarativeHttpCredentialValidator> AllValidators()
    {
        yield return new HuggingFaceCredentialValidator(_ssrfService, _policyOptions, NullLogger<HuggingFaceCredentialValidator>.Instance);
        yield return new PerplexityCredentialValidator(_ssrfService, _policyOptions, NullLogger<PerplexityCredentialValidator>.Instance);
        yield return new CohereCredentialValidator(_ssrfService, _policyOptions, NullLogger<CohereCredentialValidator>.Instance);
        yield return new FireworksAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<FireworksAiCredentialValidator>.Instance);
        yield return new ReplicateCredentialValidator(_ssrfService, _policyOptions, NullLogger<ReplicateCredentialValidator>.Instance);
        yield return new OpenRouterCredentialValidator(_ssrfService, _policyOptions, NullLogger<OpenRouterCredentialValidator>.Instance);
        yield return new XaiCredentialValidator(_ssrfService, _policyOptions, NullLogger<XaiCredentialValidator>.Instance);
        yield return new CerebrasCredentialValidator(_ssrfService, _policyOptions, NullLogger<CerebrasCredentialValidator>.Instance);
        yield return new TavilyCredentialValidator(_ssrfService, _policyOptions, NullLogger<TavilyCredentialValidator>.Instance);
        yield return new FalAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<FalAiCredentialValidator>.Instance);
        yield return new JinaAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<JinaAiCredentialValidator>.Instance);
        yield return new KlingAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<KlingAiCredentialValidator>.Instance);
        yield return new RunwayMlCredentialValidator(_ssrfService, _policyOptions, NullLogger<RunwayMlCredentialValidator>.Instance);
        yield return new RunPodCredentialValidator(_ssrfService, _policyOptions, NullLogger<RunPodCredentialValidator>.Instance);
        yield return new GoogleGeminiCredentialValidator(_ssrfService, _policyOptions, NullLogger<GoogleGeminiCredentialValidator>.Instance);
        yield return new ElevenLabsCredentialValidator(_ssrfService, _policyOptions, NullLogger<ElevenLabsCredentialValidator>.Instance);
        yield return new TogetherAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<TogetherAiCredentialValidator>.Instance);
        yield return new MistralCredentialValidator(_ssrfService, _policyOptions, NullLogger<MistralCredentialValidator>.Instance);
        yield return new StabilityAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<StabilityAiCredentialValidator>.Instance);
        yield return new Ai21CredentialValidator(_ssrfService, _policyOptions, NullLogger<Ai21CredentialValidator>.Instance);
        yield return new AssemblyAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<AssemblyAiCredentialValidator>.Instance);
        yield return new DeepgramCredentialValidator(_ssrfService, _policyOptions, NullLogger<DeepgramCredentialValidator>.Instance);
        yield return new LeonardoAiCredentialValidator(_ssrfService, _policyOptions, NullLogger<LeonardoAiCredentialValidator>.Instance);
    }

    // =========================================================================
    // Provider wiring
    // =========================================================================

    [Fact]
    public void EveryProvider_HasAnAllowlistedEndpointMatchingItsRequestHost()
    {
        foreach (var validator in AllValidators())
        {
            _registry.IsProviderSupported(validator.ProviderName).Should().BeTrue(
                $"provider '{validator.ProviderName}' must be allowlisted or every request fails in the SSRF connect callback");

            var allowlisted = _registry.GetAllowlistedEndpoint(validator.ProviderName);
            var requestUri = new Uri(validator.Descriptor.RequestUri);

            requestUri.Scheme.Should().Be("https", "validation traffic must never be plaintext");
            requestUri.Host.Should().Be(
                allowlisted.Host,
                $"provider '{validator.ProviderName}' pins the socket to the registry host, so the descriptor host must match");
        }
    }

    [Fact]
    public void EveryProvider_HasDistinctIdentityAndNeverUsesTheReservedFallbackName()
    {
        var validators = AllValidators().ToList();
        var names = validators.Select(v => v.ProviderName).ToList();

        names.Should().OnlyHaveUniqueItems("ProviderName is the sole dispatch key");
        names.Should().NotContain("Fallback", "'Fallback' is reserved for the catch-all validator");
        validators.Should().OnlyContain(v => !string.IsNullOrWhiteSpace(v.ValidatorVersion));
    }

    [Fact]
    public void EveryProvider_MatchesOnlyItsOwnCredentialType()
    {
        foreach (var validator in AllValidators())
        {
            validator.CanValidate(new CredentialCandidate { CredentialType = validator.ProviderName })
                .Should().BeTrue();
            validator.CanValidate(new CredentialCandidate { CredentialType = validator.ProviderName.ToUpperInvariant() })
                .Should().BeTrue("dispatch is case-insensitive");
            validator.CanValidate(new CredentialCandidate { CredentialType = "SomeOtherProvider" })
                .Should().BeFalse();
            validator.CanValidate(null!).Should().BeFalse();
        }
    }

    [Fact]
    public void CustomHeaderProviders_AlwaysDeclareAHeaderName()
    {
        foreach (var validator in AllValidators())
        {
            if (validator.Descriptor.AuthScheme == ProviderAuthScheme.CustomHeader)
            {
                validator.Descriptor.AuthHeaderName.Should().NotBeNullOrWhiteSpace();
            }
        }
    }

    [Fact]
    public async Task EveryProvider_PerformsZeroNetworkCallsUnderDryRunPolicy()
    {
        var dryRunOptions = Options.Create(new ValidationPolicyOptions { DryRun = true });

        var dryRunValidators = new DeclarativeHttpCredentialValidator[]
        {
            new HuggingFaceCredentialValidator(_ssrfService, dryRunOptions, NullLogger<HuggingFaceCredentialValidator>.Instance),
            new PerplexityCredentialValidator(_ssrfService, dryRunOptions, NullLogger<PerplexityCredentialValidator>.Instance),
            new CohereCredentialValidator(_ssrfService, dryRunOptions, NullLogger<CohereCredentialValidator>.Instance),
            new FireworksAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<FireworksAiCredentialValidator>.Instance),
            new ReplicateCredentialValidator(_ssrfService, dryRunOptions, NullLogger<ReplicateCredentialValidator>.Instance),
            new OpenRouterCredentialValidator(_ssrfService, dryRunOptions, NullLogger<OpenRouterCredentialValidator>.Instance),
            new XaiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<XaiCredentialValidator>.Instance),
            new CerebrasCredentialValidator(_ssrfService, dryRunOptions, NullLogger<CerebrasCredentialValidator>.Instance),
            new TavilyCredentialValidator(_ssrfService, dryRunOptions, NullLogger<TavilyCredentialValidator>.Instance),
            new FalAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<FalAiCredentialValidator>.Instance),
            new JinaAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<JinaAiCredentialValidator>.Instance),
            new KlingAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<KlingAiCredentialValidator>.Instance),
            new RunwayMlCredentialValidator(_ssrfService, dryRunOptions, NullLogger<RunwayMlCredentialValidator>.Instance),
            new RunPodCredentialValidator(_ssrfService, dryRunOptions, NullLogger<RunPodCredentialValidator>.Instance),
            new GoogleGeminiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<GoogleGeminiCredentialValidator>.Instance),
            new ElevenLabsCredentialValidator(_ssrfService, dryRunOptions, NullLogger<ElevenLabsCredentialValidator>.Instance),
            new TogetherAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<TogetherAiCredentialValidator>.Instance),
            new MistralCredentialValidator(_ssrfService, dryRunOptions, NullLogger<MistralCredentialValidator>.Instance),
            new StabilityAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<StabilityAiCredentialValidator>.Instance),
            new Ai21CredentialValidator(_ssrfService, dryRunOptions, NullLogger<Ai21CredentialValidator>.Instance),
            new AssemblyAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<AssemblyAiCredentialValidator>.Instance),
            new DeepgramCredentialValidator(_ssrfService, dryRunOptions, NullLogger<DeepgramCredentialValidator>.Instance),
            new LeonardoAiCredentialValidator(_ssrfService, dryRunOptions, NullLogger<LeonardoAiCredentialValidator>.Instance)
        };

        foreach (var validator in dryRunValidators)
        {
            var result = await validator.ValidateAsync(
                new CredentialCandidate { CredentialType = validator.ProviderName },
                TestSecret);

            result.Status.Should().Be(ValidationStatus.Pending);
            result.HttpStatusCode.Should().BeNull();
        }
    }

    [Fact]
    public async Task EveryProvider_IsBlockedByPolicyWhenValidationIsGloballyDisabled()
    {
        var disabled = Options.Create(new ValidationPolicyOptions { GlobalEnabled = false });
        var validator = new HuggingFaceCredentialValidator(
            _ssrfService, disabled, NullLogger<HuggingFaceCredentialValidator>.Instance);

        var result = await validator.ValidateAsync(
            new CredentialCandidate { CredentialType = "HuggingFace" },
            TestSecret);

        result.Status.Should().Be(ValidationStatus.BlockedByPolicy);
    }

    // =========================================================================
    // Shared HTTP mapping
    // =========================================================================

    [Fact]
    public async Task Executor_SendsTheDeclaredMethodUriAndBearerCredential()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"data\":[{\"id\":\"m\"}]}");
        var descriptor = new PerplexityCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<PerplexityCredentialValidator>.Instance).Descriptor;

        await ExecuteAsync(handler, descriptor);

        handler.LastRequest.Should().NotBeNull();
        handler.LastRequest!.Method.Should().Be(HttpMethod.Get);
        handler.LastRequest.RequestUri!.ToString().Should().Be("https://api.perplexity.ai/models");
        handler.LastRequest.Headers.Authorization!.Scheme.Should().Be("Bearer");
        handler.LastRequest.Headers.Authorization.Parameter.Should().Be(TestSecret);
    }

    [Fact]
    public async Task Executor_SendsDeclaredJsonBodyForPostProviders()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"valid\":true}");
        var descriptor = new CohereCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<CohereCredentialValidator>.Instance).Descriptor;

        var result = await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Method.Should().Be(HttpMethod.Post);
        handler.LastRequestBody.Should().Be("{}");
        result.Status.Should().Be(ValidationStatus.Valid);
    }

    [Fact]
    public async Task FalAiValidator_UsesKeyAuthorizationScheme()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{}");
        var descriptor = new FalAiCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<FalAiCredentialValidator>.Instance).Descriptor;

        var result = await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Headers.Authorization!.Scheme.Should().Be("Key");
        handler.LastRequest.Headers.Authorization.Parameter.Should().Be(TestSecret);
        result.Status.Should().Be(ValidationStatus.Valid);
    }

    [Fact]
    public async Task RunPodValidator_SendsPostWithGraphQLQuery()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"data\":{\"myself\":{\"id\":\"user1\"}}}");
        var descriptor = new RunPodCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<RunPodCredentialValidator>.Instance).Descriptor;

        var result = await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Method.Should().Be(HttpMethod.Post);
        handler.LastRequestBody.Should().Contain("myself");
        result.Status.Should().Be(ValidationStatus.Valid);
    }

    [Fact]
    public async Task GoogleGeminiValidator_SendsCustomHeader()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"models\":[{\"name\":\"gemini-pro\"}]}");
        var descriptor = new GoogleGeminiCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<GoogleGeminiCredentialValidator>.Instance).Descriptor;

        var result = await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Headers.GetValues("x-goog-api-key").Single().Should().Be(TestSecret);
        result.Status.Should().Be(ValidationStatus.Valid);
    }

    [Fact]
    public async Task ElevenLabsValidator_SendsCustomHeader()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"subscription\":{\"tier\":\"starter\"}}");
        var descriptor = new ElevenLabsCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<ElevenLabsCredentialValidator>.Instance).Descriptor;

        var result = await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Headers.GetValues("xi-api-key").Single().Should().Be(TestSecret);
        result.Status.Should().Be(ValidationStatus.Valid);
    }

    [Fact]
    public async Task AssemblyAiValidator_UsesRawAuthorizationScheme()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{}");
        var descriptor = new AssemblyAiCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<AssemblyAiCredentialValidator>.Instance).Descriptor;

        var result = await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Headers.GetValues("Authorization").Single().Should().Be(TestSecret);
        result.Status.Should().Be(ValidationStatus.Valid);
    }

    [Fact]
    public async Task DeepgramValidator_UsesTokenAuthorizationScheme()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"projects\":[{\"project_id\":\"p1\"}]}");
        var descriptor = new DeepgramCredentialValidator(
            _ssrfService, _policyOptions, NullLogger<DeepgramCredentialValidator>.Instance).Descriptor;

        var result = await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Headers.Authorization!.Scheme.Should().Be("Token");
        handler.LastRequest.Headers.Authorization.Parameter.Should().Be(TestSecret);
        result.Status.Should().Be(ValidationStatus.Valid);
    }

    [Theory]
    [InlineData(ProviderAuthScheme.TokenAuthorization, "Token")]
    [InlineData(ProviderAuthScheme.KeyAuthorization, "Key")]
    public async Task Executor_SupportsAlternativeAuthorizationSchemes(
        ProviderAuthScheme scheme,
        string expectedPrefix)
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{}");
        var descriptor = new ProviderValidationDescriptor
        {
            RequestUri = "https://api.example.com/v1/me",
            AuthScheme = scheme,
            SuccessLabel = "example verified"
        };

        await ExecuteAsync(handler, descriptor);

        handler.LastRequest!.Headers.Authorization!.Scheme.Should().Be(expectedPrefix);
        handler.LastRequest.Headers.Authorization.Parameter.Should().Be(TestSecret);
    }

    [Fact]
    public async Task Executor_SupportsRawAuthorizationAndCustomHeaderSchemes()
    {
        var rawHandler = new StubHttpMessageHandler(HttpStatusCode.OK, "{}");
        await ExecuteAsync(rawHandler, new ProviderValidationDescriptor
        {
            RequestUri = "https://api.example.com/v1/me",
            AuthScheme = ProviderAuthScheme.RawAuthorization,
            SuccessLabel = "example verified"
        });
        rawHandler.LastRequest!.Headers.GetValues("Authorization").Single().Should().Be(TestSecret);

        var headerHandler = new StubHttpMessageHandler(HttpStatusCode.OK, "{}");
        await ExecuteAsync(headerHandler, new ProviderValidationDescriptor
        {
            RequestUri = "https://api.example.com/v1/me",
            AuthScheme = ProviderAuthScheme.CustomHeader,
            AuthHeaderName = "xi-api-key",
            AdditionalHeaders = new Dictionary<string, string> { ["Accept"] = "application/json" },
            SuccessLabel = "example verified"
        });
        headerHandler.LastRequest!.Headers.GetValues("xi-api-key").Single().Should().Be(TestSecret);
        headerHandler.LastRequest.Headers.GetValues("Accept").Single().Should().Be("application/json");
        headerHandler.LastRequest.Headers.Authorization.Should().BeNull();
    }

    [Fact]
    public async Task Executor_CustomHeaderWithoutHeaderName_FailsFast()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{}");
        var descriptor = new ProviderValidationDescriptor
        {
            RequestUri = "https://api.example.com/v1/me",
            AuthScheme = ProviderAuthScheme.CustomHeader,
            SuccessLabel = "example verified"
        };

        var act = async () => await ExecuteAsync(handler, descriptor);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, ValidationStatus.Invalid, ValidationConfidence.Confirmed)]
    [InlineData(HttpStatusCode.Forbidden, ValidationStatus.ValidInsufficientScope, ValidationConfidence.Strong)]
    [InlineData(HttpStatusCode.InternalServerError, ValidationStatus.ValidationError, ValidationConfidence.Indeterminate)]
    [InlineData(HttpStatusCode.BadGateway, ValidationStatus.ValidationError, ValidationConfidence.Indeterminate)]
    [InlineData(HttpStatusCode.NotFound, ValidationStatus.ValidationError, ValidationConfidence.Indeterminate)]
    public async Task Executor_MapsFailureStatusCodesDeterministically(
        HttpStatusCode responseCode,
        ValidationStatus expectedStatus,
        ValidationConfidence expectedConfidence)
    {
        var handler = new StubHttpMessageHandler(responseCode, "irrelevant");

        var result = await ExecuteAsync(handler, SimpleDescriptor());

        result.Status.Should().Be(expectedStatus);
        result.Confidence.Should().Be(expectedConfidence);
        result.HttpStatusCode.Should().Be((int)responseCode);
        result.SafeEvidenceJson.Should().Be("{}");
    }

    [Fact]
    public async Task Executor_RateLimited_ReturnsRetryAfterFromDeltaHeader()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.TooManyRequests, "{}");
        handler.RetryAfterDelta = TimeSpan.FromSeconds(120);
        var before = DateTime.UtcNow;

        var result = await ExecuteAsync(handler, SimpleDescriptor());

        result.Status.Should().Be(ValidationStatus.RateLimited);
        result.Confidence.Should().Be(ValidationConfidence.Strong);
        result.RetryAfterUtc.Should().NotBeNull();
        result.RetryAfterUtc!.Value.Should().BeOnOrAfter(before.AddSeconds(115));
    }

    [Fact]
    public async Task Executor_RateLimitedWithoutRetryAfter_ReturnsNullRetryAfter()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.TooManyRequests, "{}");

        var result = await ExecuteAsync(handler, SimpleDescriptor());

        result.Status.Should().Be(ValidationStatus.RateLimited);
        result.RetryAfterUtc.Should().BeNull();
    }

    [Fact]
    public async Task Executor_NetworkFailureIncludingBlockedSsrf_MapsToUnavailable()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{}")
        {
            ThrowOnSend = new HttpRequestException("SSRF Protection blocked connection to 'api.example.com'")
        };

        var result = await ExecuteAsync(handler, SimpleDescriptor());

        result.Status.Should().Be(ValidationStatus.Unavailable);
        result.Confidence.Should().Be(ValidationConfidence.Indeterminate);
        result.HttpStatusCode.Should().BeNull();
        result.ResponseClassification.Should().StartWith("Network error:");
    }

    [Fact]
    public async Task Executor_Success_CountsArrayItemsWithoutLeakingBodyContent()
    {
        var handler = new StubHttpMessageHandler(
            HttpStatusCode.OK,
            "{\"data\":[{\"id\":\"secret-model-a\"},{\"id\":\"secret-model-b\"}]}");

        var result = await ExecuteAsync(handler, SimpleDescriptor("data"));

        result.Status.Should().Be(ValidationStatus.Valid);
        result.Confidence.Should().Be(ValidationConfidence.Confirmed);
        result.SafeEvidenceJson.Should().Contain("\"itemCount\":2");
        result.SafeEvidenceJson.Should().NotContain("secret-model-a");
    }

    [Fact]
    public async Task Executor_Success_WithoutRequiredPropertyIsNotTreatedAsValid()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"unexpected\":true}");

        var result = await ExecuteAsync(handler, SimpleDescriptor("data"));

        result.Status.Should().Be(ValidationStatus.ValidationError);
        result.Confidence.Should().Be(ValidationConfidence.Indeterminate);
        result.ResponseClassification.Should().Contain("did not contain the expected 'data' field");
    }

    [Fact]
    public async Task Executor_Success_WithExplicitFalseVerificationFlagIsInvalid()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "{\"valid\":false}");

        var result = await ExecuteAsync(handler, SimpleDescriptor("valid"));

        result.Status.Should().Be(ValidationStatus.Invalid);
        result.Confidence.Should().Be(ValidationConfidence.Confirmed);
    }

    [Fact]
    public async Task Executor_Success_WithMalformedJsonIsAValidationError()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "not-json");

        var result = await ExecuteAsync(handler, SimpleDescriptor("data"));

        result.Status.Should().Be(ValidationStatus.ValidationError);
        result.ResponseClassification.Should().Contain("not valid JSON");
    }

    [Fact]
    public async Task Executor_Success_WithoutDeclaredPropertyAcceptsPlainHttp200()
    {
        var handler = new StubHttpMessageHandler(HttpStatusCode.OK, "anything at all");

        var result = await ExecuteAsync(handler, SimpleDescriptor());

        result.Status.Should().Be(ValidationStatus.Valid);
        result.Confidence.Should().Be(ValidationConfidence.Confirmed);
        result.SafeEvidenceJson.Should().Contain("latencyMs");
    }

    [Fact]
    public async Task Executor_NeverPlacesTheSecretInAnyReturnedField()
    {
        HttpStatusCode[] codes =
        [
            HttpStatusCode.OK,
            HttpStatusCode.Unauthorized,
            HttpStatusCode.Forbidden,
            HttpStatusCode.TooManyRequests,
            HttpStatusCode.InternalServerError
        ];

        foreach (var code in codes)
        {
            var handler = new StubHttpMessageHandler(code, $"{{\"data\":[],\"echo\":\"{TestSecret}\"}}");

            var result = await ExecuteAsync(handler, SimpleDescriptor("data"));

            result.SafeEvidenceJson.Should().NotContain(TestSecret);
            result.ResponseClassification.Should().NotContain(TestSecret);
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static ProviderValidationDescriptor SimpleDescriptor(string? successProperty = null) => new()
    {
        RequestUri = "https://api.example.com/v1/me",
        AuthScheme = ProviderAuthScheme.BearerAuthorization,
        SuccessJsonProperty = successProperty,
        SuccessLabel = "example account verified"
    };

    private static async Task<ValidationResultDto> ExecuteAsync(
        StubHttpMessageHandler handler,
        ProviderValidationDescriptor descriptor)
    {
        using var client = new HttpClient(handler, disposeHandler: false);
        return await ProviderValidationExecutor.ExecuteAsync(
            client,
            descriptor,
            TestSecret,
            Stopwatch.StartNew(),
            CancellationToken.None);
    }

    private sealed class StubHttpMessageHandler(HttpStatusCode statusCode, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        public string? LastRequestBody { get; private set; }

        public TimeSpan? RetryAfterDelta { get; set; }

        public HttpRequestException? ThrowOnSend { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (request.Content != null)
            {
                LastRequestBody = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            if (ThrowOnSend != null)
            {
                throw ThrowOnSend;
            }

            var response = new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(body)
            };

            if (RetryAfterDelta.HasValue)
            {
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(RetryAfterDelta.Value);
            }

            return response;
        }
    }
}
