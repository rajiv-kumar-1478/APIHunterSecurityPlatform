namespace Platform.Infrastructure.Validators;

/// <summary>
/// How a provider expects the credential to be presented.
/// </summary>
public enum ProviderAuthScheme
{
    /// <summary><c>Authorization: Bearer {secret}</c>.</summary>
    BearerAuthorization = 1,

    /// <summary><c>Authorization: Token {secret}</c>.</summary>
    TokenAuthorization = 2,

    /// <summary><c>Authorization: Key {secret}</c>.</summary>
    KeyAuthorization = 3,

    /// <summary><c>Authorization: {secret}</c> with no scheme prefix.</summary>
    RawAuthorization = 4,

    /// <summary>A provider-specific header, e.g. <c>xi-api-key: {secret}</c>.</summary>
    CustomHeader = 5
}

/// <summary>
/// Declarative description of a single provider's credential-validation request.
///
/// The destination is a server-controlled absolute HTTPS literal. Its host must match the
/// provider's <c>ValidationEndpointRegistry</c> origin, because the SSRF handler pins the
/// socket to the registry-resolved address while TLS SNI still uses this request host.
/// Candidate-supplied URLs are never accepted.
/// </summary>
public sealed record ProviderValidationDescriptor
{
    public required string RequestUri { get; init; }

    public required ProviderAuthScheme AuthScheme { get; init; }

    public HttpMethod Method { get; init; } = HttpMethod.Get;

    /// <summary>Header name, required when <see cref="AuthScheme"/> is <see cref="ProviderAuthScheme.CustomHeader"/>.</summary>
    public string? AuthHeaderName { get; init; }

    /// <summary>Additional non-secret request headers required by the provider.</summary>
    public IReadOnlyDictionary<string, string>? AdditionalHeaders { get; init; }

    /// <summary>Optional JSON request body sent as <c>application/json</c>.</summary>
    public string? JsonBody { get; init; }

    /// <summary>
    /// Optional top-level JSON property that must be present on a 200 response for the
    /// credential to be treated as verified. When null, HTTP 200 alone is sufficient.
    /// </summary>
    public string? SuccessJsonProperty { get; init; }

    /// <summary>Short human label used in <c>ResponseClassification</c>. Must never contain secrets.</summary>
    public required string SuccessLabel { get; init; }
}
