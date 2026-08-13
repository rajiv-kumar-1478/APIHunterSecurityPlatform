namespace Platform.Domain.Contracts;

public sealed record ProtectedCredential(
    string ProviderKey,
    string ResourceReference,
    string RawCredentialValue);
