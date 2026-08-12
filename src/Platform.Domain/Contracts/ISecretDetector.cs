using Platform.Domain.Entities;

namespace Platform.Domain.Contracts;

/// <summary>
/// Transient internal secret match object within the trusted pipeline.
/// Plaintext raw values are discarded immediately after HMAC fingerprinting, masking, and DataProtection encryption.
/// </summary>
public record SecretMatchInternal(
    string RuleId,
    int RuleVersion,
    string CredentialType,
    string Confidence,
    string RawMatchValue,
    string MaskedValue,
    int LineNumber,
    int MatchStartIndex,
    int MatchLength,
    string RedactedLineContent,
    string RawLineContent);

public interface ISecretDetector
{
    Task<IReadOnlyList<SecretMatchInternal>> ScanFileAsync(
        string filePath,
        string fileContent,
        IReadOnlyList<DetectionRule> rules,
        CancellationToken ct = default);
}
