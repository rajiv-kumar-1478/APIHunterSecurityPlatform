using System;

namespace Platform.Domain.Entities;

public class SecurityProviderCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string ProviderKey { get; set; } = string.Empty;

    public string SecretReference { get; set; } = string.Empty;

    public string CredentialType { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public DateTime? LastValidatedAtUtc { get; set; }

    public string ValidationStatus { get; set; } = "Valid";

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
