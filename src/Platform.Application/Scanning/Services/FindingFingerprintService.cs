using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Services;

/// <summary>
/// Authoritative implementation of the v1 canonical fingerprinting specification.
/// </summary>
public sealed class FindingFingerprintService : IFindingFingerprintService
{
    private const string AlgorithmVersion = "v1";

    public string ComputeCanonicalFingerprint(
        string targetUrl,
        string findingType,
        string? httpMethod = null,
        string? parameterName = null,
        string? vulnerableLocation = null,
        string? ruleOrTemplateId = null)
    {
        var canonicalUrl = NormalizeUrl(targetUrl);
        var canonicalFindingType = NormalizeFindingType(findingType);
        var canonicalMethod = NormalizeHttpMethod(httpMethod);
        var canonicalParam = NormalizeParameter(parameterName);
        var canonicalLocation = NormalizeLocation(vulnerableLocation);
        var canonicalRule = NormalizeRule(ruleOrTemplateId);

        var rawInput = $"{AlgorithmVersion}\n" +
                       $"{canonicalUrl}\n" +
                       $"{canonicalFindingType}\n" +
                       $"{canonicalMethod}\n" +
                       $"{canonicalParam}\n" +
                       $"{canonicalLocation}\n" +
                       $"{canonicalRule}";

        var normalizedNfc = rawInput.Normalize(NormalizationForm.FormC);
        var inputBytes = Encoding.UTF8.GetBytes(normalizedNfc);
        var hashBytes = SHA256.HashData(inputBytes);

        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public string ComputeCanonicalFingerprint(FindingCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        return ComputeCanonicalFingerprint(
            candidate.TargetUrl,
            candidate.FindingType.ToString(),
            candidate.HttpMethod,
            candidate.ParameterName,
            candidate.VulnerableLocation,
            candidate.RuleOrTemplateId ?? candidate.TemplateId
        );
    }

    private static string NormalizeUrl(string? rawUrl)
    {
        if (string.IsNullOrWhiteSpace(rawUrl))
            return string.Empty;

        rawUrl = rawUrl.Trim();

        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
        {
            // Fallback for relative or malformed URIs
            return rawUrl.ToLowerInvariant().TrimEnd('/');
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        var host = uri.Host.ToLowerInvariant();
        var port = uri.Port;

        // Strip default ports
        var isDefaultPort = (scheme == "http" && port == 80) ||
                            (scheme == "https" && port == 443);

        var hostAndPort = isDefaultPort || port <= 0
            ? host
            : $"{host}:{port}";

        var path = uri.AbsolutePath;
        if (path == "/" || string.IsNullOrEmpty(path))
        {
            path = string.Empty;
        }
        else if (path.EndsWith('/') && path.Length > 1)
        {
            path = path.TrimEnd('/');
        }

        // Sort query parameters alphabetically
        var query = uri.Query;
        var canonicalQuery = string.Empty;

        if (!string.IsNullOrEmpty(query))
        {
            var trimmedQuery = query.TrimStart('?');
            if (!string.IsNullOrEmpty(trimmedQuery))
            {
                var pairs = trimmedQuery.Split('&', StringSplitOptions.RemoveEmptyEntries);
                var sortedPairs = pairs
                    .Select(p =>
                    {
                        var parts = p.Split('=', 2);
                        var key = Uri.UnescapeDataString(parts[0]).Trim();
                        var val = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]).Trim() : string.Empty;
                        return (Key: key, Value: val);
                    })
                    .OrderBy(p => p.Key, StringComparer.Ordinal)
                    .ThenBy(p => p.Value, StringComparer.Ordinal)
                    .Select(p => string.IsNullOrEmpty(p.Value) ? Uri.EscapeDataString(p.Key) : $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}");

                canonicalQuery = "?" + string.Join("&", sortedPairs);
            }
        }

        return $"{scheme}://{hostAndPort}{path}{canonicalQuery}";
    }

    private static string NormalizeFindingType(string? findingType)
    {
        if (string.IsNullOrWhiteSpace(findingType))
            return string.Empty;

        return findingType.Trim().ToLowerInvariant().Replace(' ', '-').Replace('_', '-');
    }

    private static string NormalizeHttpMethod(string? method)
    {
        if (string.IsNullOrWhiteSpace(method))
            return string.Empty;

        return method.Trim().ToUpperInvariant();
    }

    private static string NormalizeParameter(string? parameter)
    {
        if (string.IsNullOrWhiteSpace(parameter))
            return string.Empty;

        return parameter.Trim().ToLowerInvariant();
    }

    private static string NormalizeLocation(string? location)
    {
        if (string.IsNullOrWhiteSpace(location))
            return string.Empty;

        return location.Trim().ToLowerInvariant();
    }

    private static string NormalizeRule(string? ruleOrTemplateId)
    {
        if (string.IsNullOrWhiteSpace(ruleOrTemplateId))
            return string.Empty;

        return ruleOrTemplateId.Trim().ToLowerInvariant();
    }
}
