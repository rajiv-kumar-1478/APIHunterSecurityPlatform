using System.Security.Cryptography;
using System.Text;

namespace Platform.Domain.ValueObjects;

public static class FingerprintUtils
{
    public static string ComputeSecretFingerprint(string rawSecret, string pepper, int pepperVersion = 1)
    {
        var normalizedSecret = NormalizeSecret(rawSecret);
        var keyBytes = Encoding.UTF8.GetBytes($"{pepper}_v{pepperVersion}");
        using var hmac = new HMACSHA256(keyBytes);
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(normalizedSecret));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public static string ComputeOccurrenceFingerprint(
        Guid candidateId,
        Guid snapshotFileId,
        string ruleId,
        int ruleVersion,
        int lineNumber,
        int matchStartIndex,
        int matchLength)
    {
        var raw = $"{candidateId}:{snapshotFileId}:{ruleId}:v{ruleVersion}:{lineNumber}:{matchStartIndex}:{matchLength}";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public static string ComputeSha256(string rawInput)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawInput ?? string.Empty));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public static string MaskSecret(string rawSecret)
    {
        if (string.IsNullOrWhiteSpace(rawSecret)) return "*****";
        if (rawSecret.Length <= 8) return $"{rawSecret[0]}****{rawSecret[^1]}";
        return $"{rawSecret[..4]}****{rawSecret[^4..]}";
    }

    public static string RedactLine(string rawLine, string secretToRedact)
    {
        if (string.IsNullOrEmpty(rawLine) || string.IsNullOrEmpty(secretToRedact)) return rawLine;
        return rawLine.Replace(secretToRedact, "****REDACTED****");
    }

    private static string NormalizeSecret(string secret)
    {
        var trimmed = secret.Trim();
        if ((trimmed.StartsWith('"') && trimmed.EndsWith('"')) || (trimmed.StartsWith('\'') && trimmed.EndsWith('\'')))
        {
            trimmed = trimmed[1..^1].Trim();
        }
        return trimmed;
    }
}
