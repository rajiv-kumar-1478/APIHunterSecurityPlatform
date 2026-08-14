using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript.Contracts;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Second-layer defense boundary projecting raw finding evidence into a safe, bounded,
/// and strictly redacted AI prompt payload.
/// </summary>
public static class AiEvidenceProjector
{
    public const int MaxSnippetChars = 500;
    public const int MaxTotalPromptChars = 2000;

    private static readonly Regex AuthTokenRegex = new(
        @"(?:Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(200));

    private static readonly Regex SecretAssignmentRegex = new(
        @"(?:key|secret|token|password|auth|credential|api_key)\s*[:=]\s*['""][^'""]{8,}['""]",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(200));

    public static ProjectedAiEvidence ProjectEvidence(Guid findingId, FindingCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        // 1. Sanitize code snippet & enforce length boundary
        var rawSnippet = candidate.Description ?? candidate.RawEvidenceJson ?? string.Empty;
        var sanitizedSnippet = RedactSensitiveMaterial(rawSnippet);

        if (sanitizedSnippet.Length > MaxSnippetChars)
        {
            sanitizedSnippet = sanitizedSnippet[..MaxSnippetChars] + " ... [truncated]";
        }

        // 2. Build sanitized context details
        var contextDetails = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(candidate.EndpointPath))
        {
            contextDetails["EndpointPath"] = RedactSensitiveMaterial(candidate.EndpointPath);
        }
        if (!string.IsNullOrWhiteSpace(candidate.CweId))
        {
            contextDetails["CweId"] = candidate.CweId;
        }
        if (!string.IsNullOrWhiteSpace(candidate.RawSeverity))
        {
            contextDetails["ScannerSeverity"] = candidate.RawSeverity;
        }

        // 3. Estimate prompt tokens (roughly 4 chars per token)
        var totalLength = sanitizedSnippet.Length + candidate.Title.Length + (candidate.EndpointPath?.Length ?? 0);
        var tokenEstimate = Math.Max(1, totalLength / 4);

        return new ProjectedAiEvidence(
            FindingId: findingId,
            RuleOrTemplateId: candidate.RuleOrTemplateId,
            FindingTitle: candidate.Title,
            TargetEndpoint: RedactSensitiveMaterial(candidate.EndpointPath ?? candidate.TargetUrl),
            HttpMethod: candidate.HttpMethod,
            ParameterName: candidate.ParameterName,
            SanitizedCodeSnippet: sanitizedSnippet,
            SanitizedContextDetails: contextDetails,
            PromptTokenEstimate: tokenEstimate
        );
    }

    public static string RedactSensitiveMaterial(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;

        var result = input;
        try
        {
            result = AuthTokenRegex.Replace(result, "[REDACTED_SECRET_TOKEN]");
            result = SecretAssignmentRegex.Replace(result, "key: '[REDACTED_SECRET_VALUE]'");
        }
        catch
        {
            // Regex timeout fallback
            return "[REDACTED_DUE_TO_TIMEOUT]";
        }

        return result;
    }
}
