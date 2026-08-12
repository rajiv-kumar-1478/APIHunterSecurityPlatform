using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Adapters.Detection;


public class RegexSecretDetector(
    IOptions<DetectionOptions> options,
    ILogger<RegexSecretDetector> logger) : ISecretDetector
{
    public Task<IReadOnlyList<SecretMatchInternal>> ScanFileAsync(
        string filePath,
        string fileContent,
        IReadOnlyList<DetectionRule> rules,
        CancellationToken ct = default)
    {
        var results = new List<SecretMatchInternal>();
        if (string.IsNullOrWhiteSpace(fileContent))
        {
            return Task.FromResult<IReadOnlyList<SecretMatchInternal>>(results);
        }

        var opts = options.Value;
        var maxBytes = opts.MaxFileSizeMb * 1024 * 1024;
        if (Encoding.UTF8.GetByteCount(fileContent) > maxBytes)
        {
            logger.LogWarning("File {FilePath} exceeds max size limit ({MaxMb}MB). Skipping detection.", filePath, opts.MaxFileSizeMb);
            return Task.FromResult<IReadOnlyList<SecretMatchInternal>>(results);
        }

        var lines = fileContent.Split(["\r\n", "\r", "\n"], StringSplitOptions.None);
        var timeout = TimeSpan.FromSeconds(opts.RegexTimeoutSeconds);

        foreach (var rule in rules.Where(r => r.IsEnabled))
        {
            ct.ThrowIfCancellationRequested();

            if (results.Count >= opts.MaxMatchesPerFile)
            {
                logger.LogWarning("Max matches per file ({Max}) reached for {FilePath}. Stopping scan.", opts.MaxMatchesPerFile, filePath);
                break;
            }

            try
            {
                var regex = new Regex(
                    rule.RegexPattern,
                    RegexOptions.Compiled | RegexOptions.NonBacktracking,
                    timeout);

                var matches = regex.Matches(fileContent);

                foreach (Match match in matches)
                {
                    ct.ThrowIfCancellationRequested();

                    if (!match.Success || string.IsNullOrWhiteSpace(match.Value))
                    {
                        continue;
                    }

                    // Extract raw candidate match string
                    var rawMatch = match.Value;

                    // Apply allowlist patterns if configured for rule
                    if (IsAllowlisted(rawMatch, rule.AllowlistPatternsJson))
                    {
                        continue;
                    }

                    // Determine line number and line context
                    var (lineNumber, rawLine, matchStartInLine, matchLength) = CalculateLineContext(fileContent, lines, match.Index, match.Length);
                    var redactedLine = FingerprintUtils.RedactLine(rawLine, rawMatch);
                    var maskedValue = FingerprintUtils.MaskSecret(rawMatch);

                    results.Add(new SecretMatchInternal(
                        RuleId: rule.Id,
                        RuleVersion: rule.Version,
                        CredentialType: rule.CredentialType,
                        Confidence: rule.Confidence,
                        RawMatchValue: rawMatch,
                        MaskedValue: maskedValue,
                        LineNumber: lineNumber,
                        MatchStartIndex: matchStartInLine,
                        MatchLength: matchLength,
                        RedactedLineContent: redactedLine,
                        RawLineContent: rawLine));

                    if (results.Count >= opts.MaxMatchesPerFile)
                    {
                        break;
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                logger.LogWarning("Regex match timeout ({Timeout}s) for rule {RuleId} v{Version} on file {FilePath}",
                    opts.RegexTimeoutSeconds, rule.Id, rule.Version, filePath);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error executing rule {RuleId} v{Version} on file {FilePath}",
                    rule.Id, rule.Version, filePath);
            }
        }

        return Task.FromResult<IReadOnlyList<SecretMatchInternal>>(results);
    }

    public static string ComputeSecretFingerprint(string rawSecret, string pepper, int pepperVersion = 1) =>
        FingerprintUtils.ComputeSecretFingerprint(rawSecret, pepper, pepperVersion);

    public static string ComputeOccurrenceFingerprint(
        Guid candidateId,
        Guid snapshotFileId,
        string ruleId,
        int ruleVersion,
        int lineNumber,
        int matchStartIndex,
        int matchLength) =>
        FingerprintUtils.ComputeOccurrenceFingerprint(candidateId, snapshotFileId, ruleId, ruleVersion, lineNumber, matchStartIndex, matchLength);

    public static string MaskSecret(string rawSecret) =>
        FingerprintUtils.MaskSecret(rawSecret);

    public static string RedactLine(string rawLine, string secretToRedact) =>
        FingerprintUtils.RedactLine(rawLine, secretToRedact);


    private static string NormalizeSecret(string secret)
    {
        // Secret normalization: trim outer single/double quotes or leading/trailing whitespace
        var trimmed = secret.Trim();
        if ((trimmed.StartsWith('"') && trimmed.EndsWith('"')) || (trimmed.StartsWith('\'') && trimmed.EndsWith('\'')))
        {
            trimmed = trimmed[1..^1].Trim();
        }
        return trimmed;
    }

    private static bool IsAllowlisted(string matchValue, string? allowlistPatternsJson)
    {
        if (string.IsNullOrWhiteSpace(allowlistPatternsJson)) return false;
        try
        {
            var patterns = System.Text.Json.JsonSerializer.Deserialize<List<string>>(allowlistPatternsJson);
            if (patterns is null) return false;

            foreach (var pattern in patterns)
            {
                if (Regex.IsMatch(matchValue, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Ignore deserialization or regex failures in allowlist
        }
        return false;
    }

    private static (int LineNumber, string RawLine, int MatchStartInLine, int MatchLength) CalculateLineContext(
        string fullContent, string[] lines, int matchIndex, int matchLength)
    {
        int currentPos = 0;
        for (int i = 0; i < lines.Length; i++)
        {
            int lineLen = lines[i].Length + 1; // +1 for newline delimiter estimate
            if (currentPos + lineLen > matchIndex)
            {
                int lineNumber = i + 1;
                string rawLine = lines[i];
                int startInLine = Math.Max(0, matchIndex - currentPos);
                return (lineNumber, rawLine, startInLine, matchLength);
            }
            currentPos += lineLen;
        }

        return (1, lines.Length > 0 ? lines[0] : string.Empty, 0, matchLength);
    }
}
