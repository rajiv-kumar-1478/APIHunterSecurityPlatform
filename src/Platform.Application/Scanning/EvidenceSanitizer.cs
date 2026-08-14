using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

/// <summary>
/// Structured evidence sanitizer enforcing strict data-protection and DoS prevention boundaries.
/// Strips non-printable control characters, masks credentials/tokens, redacts sensitive query parameters,
/// and bounds payload sizes to 64 KiB.
/// </summary>
public static class EvidenceSanitizer
{
    private static readonly Regex ControlCharRegex = new(@"[^\x20-\x7E\r\n\t]", RegexOptions.Compiled);

    private static readonly Regex PrivateKeyRegex = new(
        @"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+PRIVATE KEY-----",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex BearerTokenRegex = new(
        @"(?i)\b(bearer\s+)([A-Za-z0-9_\-\.]{16,})",
        RegexOptions.Compiled);

    private static readonly Regex SensitiveKeyPattern = new(
        @"(?i)([""']?(?:api[_-]?key|apikey|secret|password|passwd|auth[_-]?token|token|access[_-]?token|client[_-]?secret|private[_-]?key)[""']?\s*[:=]\s*[""']?)([^""',\s\}]{6,})([""']?)",
        RegexOptions.Compiled);

    private static readonly Regex SensitiveQueryParamRegex = new(
        @"(?i)([\?&](?:token|key|api_key|apikey|secret|password|auth|sig|signature)=)([^&\s#]+)",
        RegexOptions.Compiled);

    /// <summary>
    /// Sanitizes raw evidence string: strips control chars, redacts secrets, and bounds size.
    /// </summary>
    public static string SanitizeEvidence(string? rawEvidence, int maxSizeBytes = 64 * 1024)
    {
        if (string.IsNullOrWhiteSpace(rawEvidence)) return "{}";

        // 1. Strip non-printable control characters
        var sanitized = ControlCharRegex.Replace(rawEvidence, string.Empty);

        // 2. Redact Private Keys
        sanitized = PrivateKeyRegex.Replace(sanitized, "[REDACTED_PRIVATE_KEY]");

        // 3. Redact Bearer Tokens
        sanitized = BearerTokenRegex.Replace(sanitized, "$1[REDACTED_TOKEN]");

        // 4. Redact Key-Value Secrets
        sanitized = SensitiveKeyPattern.Replace(sanitized, "$1[REDACTED]$3");

        // 5. Redact Sensitive Query Parameters
        sanitized = SensitiveQueryParamRegex.Replace(sanitized, "$1[REDACTED]");

        // 6. Bound payload size
        var bytes = Encoding.UTF8.GetBytes(sanitized);
        if (bytes.Length > maxSizeBytes)
        {
            var truncated = Encoding.UTF8.GetString(bytes, 0, maxSizeBytes - 32) + "... [TRUNCATED_TO_64KB]";
            return truncated;
        }

        return sanitized;
    }

    /// <summary>
    /// Redacts sensitive query parameters from a URL while preserving scheme, host, and path structure.
    /// </summary>
    public static string SanitizeUrl(string rawUrl)
    {
        if (string.IsNullOrWhiteSpace(rawUrl)) return string.Empty;
        return SensitiveQueryParamRegex.Replace(rawUrl.Trim(), "$1[REDACTED]");
    }

    /// <summary>
    /// Sanitizes and limits attribute dictionaries to prevent DoS via payload amplification.
    /// </summary>
    public static IReadOnlyDictionary<string, string> SanitizeAttributes(
        IReadOnlyDictionary<string, string>? attributes,
        ParserResourceBounds bounds)
    {
        if (attributes == null || attributes.Count == 0)
        {
            return new Dictionary<string, string>();
        }

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var count = 0;

        foreach (var kvp in attributes)
        {
            if (count >= bounds.MaxAttributesCount) break;
            if (string.IsNullOrWhiteSpace(kvp.Key)) continue;

            var safeKey = ControlCharRegex.Replace(kvp.Key.Trim(), string.Empty);
            var rawVal = kvp.Value ?? string.Empty;
            var safeVal = SanitizeEvidence(rawVal, bounds.MaxAttributeValueLength);

            if (safeVal.Length > bounds.MaxAttributeValueLength)
            {
                safeVal = safeVal.Substring(0, bounds.MaxAttributeValueLength);
            }

            result[safeKey] = safeVal;
            count++;
        }

        return result;
    }
}
