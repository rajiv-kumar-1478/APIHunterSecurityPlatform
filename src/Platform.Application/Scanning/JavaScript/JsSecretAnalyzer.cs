using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Acornima;
using Acornima.Ast;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.JavaScript;

/// <summary>
/// Authoritative JavaScript secret and sensitive-value intelligence engine.
/// Combines regex pattern detection with AST usage context, Shannon entropy analysis,
/// source map extraction, cross-chunk deduplication, and strict cleartext redaction.
/// </summary>
public sealed class JsSecretAnalyzer : IJsSecretAnalyzer
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(500);

    private static readonly (string PatternId, string SecretType, SecretCategory Category, Regex Regex, string DefaultSeverity)[] SecretPatterns = new[]
    {
        ("aws-access-key", "AWS Access Key", SecretCategory.CloudCredential, new Regex(@"\b(AKIA[0-9A-Z]{16})\b", RegexOptions.Compiled, RegexTimeout), "medium"),
        ("github-token", "GitHub Token", SecretCategory.ApiKey, new Regex(@"\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b", RegexOptions.Compiled, RegexTimeout), "medium"),
        ("stripe-secret-key", "Stripe Secret Key", SecretCategory.ApiKey, new Regex(@"\b(sk_live_[0-9a-zA-Z]{24,})\b", RegexOptions.Compiled, RegexTimeout), "medium"),
        ("stripe-publishable-key", "Stripe Publishable Key", SecretCategory.ApiKey, new Regex(@"\b(pk_live_[0-9a-zA-Z]{24,})\b", RegexOptions.Compiled, RegexTimeout), "low"),
        ("google-api-key", "Google API Key", SecretCategory.ApiKey, new Regex(@"\b(AIza[0-9A-Za-z\-_]{35})\b", RegexOptions.Compiled, RegexTimeout), "medium"),
        ("slack-token", "Slack Token", SecretCategory.OAuthToken, new Regex(@"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b", RegexOptions.Compiled, RegexTimeout), "medium"),
        ("jwt-token", "JSON Web Token", SecretCategory.OAuthToken, new Regex(@"\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b", RegexOptions.Compiled, RegexTimeout), "low"),
        ("private-key-header", "Private Key", SecretCategory.PrivateKey, new Regex(@"(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY-----)", RegexOptions.Compiled, RegexTimeout), "high"),
        ("database-connection-uri", "Database Connection URI", SecretCategory.DatabaseUri, new Regex(@"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s""'<>]+)\b", RegexOptions.Compiled, RegexTimeout), "medium")
    };

    private static readonly Regex InternalHostRegex = new(
        @"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*\.)+(?:internal|corp|local|staging|intranet))\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexTimeout);

    private static readonly HashSet<string> KnownDummyTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "sk_live_dummy",
        "pk_live_dummy",
        "test-api-key-12345",
        "test_secret_key"
    };

    public const int MaxMatchesPerAsset = 50;
    public const int MaxTotalMatches = 500;
    public const int MaxSnippetLength = 512;

    private readonly ILogger<JsSecretAnalyzer> _logger;

    public JsSecretAnalyzer(ILogger<JsSecretAnalyzer> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public JsSecretAnalysisResult AnalyzeSecrets(
        Guid scanJobId,
        IReadOnlyList<(JavaScriptAsset Asset, string JsCode)> assets)
    {
        if (assets == null || assets.Count == 0)
        {
            return new JsSecretAnalysisResult(
                FindingCandidates: Array.Empty<FindingCandidate>(),
                DiscoveredInternalHosts: Array.Empty<string>(),
                TotalSecretsDetected: 0,
                DeduplicatedSecretsCount: 0,
                GeneratedAtUtc: DateTime.UtcNow
            );
        }

        var candidateMap = new Dictionary<string, DiscoveredSecretCandidate>(StringComparer.Ordinal);
        var discoveredHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int totalMatches = 0;

        foreach (var (asset, jsCode) in assets)
        {
            if (string.IsNullOrWhiteSpace(jsCode)) continue;
            if (totalMatches >= MaxTotalMatches) break;

            int assetMatches = 0;

            // 1. Process Source Map assets (unpack sourcesContent if JSON)
            if (asset.AssetType == JsAssetType.JavaScriptMap)
            {
                ProcessSourceMapAsset(asset, jsCode, candidateMap, discoveredHosts, ref totalMatches);
                continue;
            }

            // 2. Discover Internal Infrastructure Hostnames (collected as attack-surface facts, not secret findings)
            try
            {
                var hostMatches = InternalHostRegex.Matches(jsCode);
                foreach (Match match in hostMatches)
                {
                    var host = match.Groups[1].Value.ToLowerInvariant();
                    discoveredHosts.Add(host);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Internal host regex timed out on asset '{Url}'.", asset.CanonicalUrl);
            }

            // 3. Optional AST construction for usage context
            Program? astProgram = null;
            try
            {
                var parser = new Parser(new ParserOptions { Tolerant = true });
                astProgram = parser.ParseScript(jsCode);
            }
            catch
            {
                // Tolerant fallback - AST context is an enhancer, not a hard blocker
            }

            bool isTestAsset = IsTestOrMockAsset(asset.CanonicalUrl);

            // 4. Evaluate Secret Patterns
            foreach (var rule in SecretPatterns)
            {
                if (assetMatches >= MaxMatchesPerAsset || totalMatches >= MaxTotalMatches) break;

                try
                {
                    var matches = rule.Regex.Matches(jsCode);
                    foreach (Match match in matches)
                    {
                        if (assetMatches >= MaxMatchesPerAsset || totalMatches >= MaxTotalMatches) break;

                        var rawToken = match.Groups[1].Value;
                        if (string.IsNullOrWhiteSpace(rawToken)) continue;

                        assetMatches++;
                        totalMatches++;

                        var digest = ComputeSha256(rawToken);
                        var redacted = RedactToken(rawToken);
                        var entropy = CalculateShannonEntropy(rawToken);
                        var snippet = ExtractBoundedRedactedSnippet(jsCode, match.Index, match.Length, rawToken, redacted);

                        // Determine AST Usage Context & Confidence
                        var usageContext = DetermineUsageContext(astProgram, rawToken, isTestAsset);
                        var confidence = CalculateConfidence(rule.Category, rawToken, entropy, usageContext, isTestAsset);

                        if (candidateMap.TryGetValue(digest, out var existing))
                        {
                            // Aggregate cross-chunk URLs
                            var updatedUrls = existing.DiscoveredInAssetUrls.Contains(asset.CanonicalUrl)
                                ? existing.DiscoveredInAssetUrls
                                : existing.DiscoveredInAssetUrls.Concat(new[] { asset.CanonicalUrl }).ToList();

                            // Elevate confidence if found in a more critical context in this chunk
                            var elevatedConfidence = confidence > existing.Confidence ? confidence : existing.Confidence;

                            candidateMap[digest] = existing with
                            {
                                DiscoveredInAssetUrls = updatedUrls,
                                Confidence = elevatedConfidence
                            };
                        }
                        else
                        {
                            var candidate = new DiscoveredSecretCandidate(
                                PatternId: rule.PatternId,
                                SecretType: rule.SecretType,
                                Category: rule.Category,
                                RedactedValue: redacted,
                                SecretIdentityDigest: digest,
                                ShannonEntropy: entropy,
                                DiscoveredInAssetUrls: new[] { asset.CanonicalUrl },
                                OriginalSourceFiles: null,
                                UsageContext: usageContext,
                                Provenance: asset.AssetType == JsAssetType.InlineScript ? SourceProvenance.InlineScript : SourceProvenance.ProductionBundle,
                                Confidence: confidence,
                                BoundedSnippet: snippet,
                                LineNumber: GetLineNumber(jsCode, match.Index),
                                ColumnNumber: GetColumnNumber(jsCode, match.Index)
                            );

                            candidateMap[digest] = candidate;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Regex evaluation timed out for pattern '{PatternId}' on '{Url}'.", rule.PatternId, asset.CanonicalUrl);
                }
            }
        }

        // 5. Convert DiscoveredSecretCandidate into Platform FindingCandidate records
        var findingCandidates = new List<FindingCandidate>();
        foreach (var candidate in candidateMap.Values)
        {
            var evidenceDict = new Dictionary<string, object>
            {
                ["pattern_id"] = candidate.PatternId,
                ["secret_type"] = candidate.SecretType,
                ["category"] = candidate.Category.ToString(),
                ["redacted_value"] = candidate.RedactedValue,
                ["shannon_entropy"] = Math.Round(candidate.ShannonEntropy, 2),
                ["usage_context"] = candidate.UsageContext.ToString(),
                ["provenance"] = candidate.Provenance.ToString(),
                ["confidence"] = candidate.Confidence.ToString(),
                ["occurrences_count"] = candidate.DiscoveredInAssetUrls.Count,
                ["discovered_in_assets"] = candidate.DiscoveredInAssetUrls,
                ["original_source_files"] = candidate.OriginalSourceFiles ?? Array.Empty<string>(),
                ["snippet"] = candidate.BoundedSnippet
            };

            var rawEvidenceJson = JsonSerializer.Serialize(evidenceDict);
            var rootUrl = candidate.DiscoveredInAssetUrls.FirstOrDefault() ?? "https://app.example.com";
            var ruleDef = SecretPatterns.FirstOrDefault(p => p.PatternId == candidate.PatternId);
            var severity = ruleDef.DefaultSeverity ?? "medium";

            var findingCandidate = new FindingCandidate(
                ToolKey: "jsminer",
                ToolVersion: "1.2.0",
                FindingType: FindingType.UnvalidatedCredentialExposed,
                Title: $"Unvalidated {candidate.SecretType} Discovered in JavaScript",
                Description: $"Discovered potential {candidate.SecretType} ({candidate.RedactedValue}) across {candidate.DiscoveredInAssetUrls.Count} JavaScript asset(s). Context: {candidate.UsageContext}.",
                RawSeverity: severity,
                TargetUrl: rootUrl,
                RuleOrTemplateId: candidate.PatternId,
                RawEvidenceJson: rawEvidenceJson,
                ObservedAtUtc: DateTime.UtcNow
            );

            findingCandidates.Add(findingCandidate);
        }

        return new JsSecretAnalysisResult(
            FindingCandidates: findingCandidates.AsReadOnly(),
            DiscoveredInternalHosts: discoveredHosts.ToList().AsReadOnly(),
            TotalSecretsDetected: totalMatches,
            DeduplicatedSecretsCount: candidateMap.Count,
            GeneratedAtUtc: DateTime.UtcNow
        );
    }

    private void ProcessSourceMapAsset(
        JavaScriptAsset asset,
        string mapJson,
        Dictionary<string, DiscoveredSecretCandidate> candidateMap,
        HashSet<string> discoveredHosts,
        ref int totalMatches)
    {
        try
        {
            using var doc = JsonDocument.Parse(mapJson);
            if (!doc.RootElement.TryGetProperty("sources", out var sourcesElement) ||
                !doc.RootElement.TryGetProperty("sourcesContent", out var sourcesContentElement))
            {
                return;
            }

            var sources = sourcesElement.EnumerateArray().Select(s => s.GetString() ?? "unknown").ToList();
            var contents = sourcesContentElement.EnumerateArray().Select(c => c.GetString() ?? string.Empty).ToList();

            for (int i = 0; i < Math.Min(sources.Count, contents.Count); i++)
            {
                if (totalMatches >= MaxTotalMatches) break;

                var sourcePath = sources[i];
                var sourceCode = contents[i];
                if (string.IsNullOrWhiteSpace(sourceCode)) continue;

                bool isTest = IsTestOrMockAsset(sourcePath);

                foreach (var rule in SecretPatterns)
                {
                    if (totalMatches >= MaxTotalMatches) break;

                    var matches = rule.Regex.Matches(sourceCode);
                    foreach (Match match in matches)
                    {
                        if (totalMatches >= MaxTotalMatches) break;

                        var rawToken = match.Groups[1].Value;
                        if (string.IsNullOrWhiteSpace(rawToken)) continue;

                        totalMatches++;
                        var digest = ComputeSha256(rawToken);
                        var redacted = RedactToken(rawToken);
                        var entropy = CalculateShannonEntropy(rawToken);
                        var snippet = ExtractBoundedRedactedSnippet(sourceCode, match.Index, match.Length, rawToken, redacted);
                        var usageContext = isTest ? AstUsageContext.TestOrExample : AstUsageContext.StandaloneStringLiteral;
                        var confidence = CalculateConfidence(rule.Category, rawToken, entropy, usageContext, isTest);

                        if (candidateMap.TryGetValue(digest, out var existing))
                        {
                            var updatedSources = existing.OriginalSourceFiles != null
                                ? existing.OriginalSourceFiles.Concat(new[] { sourcePath }).Distinct().ToList()
                                : new List<string> { sourcePath };

                            candidateMap[digest] = existing with
                            {
                                OriginalSourceFiles = updatedSources
                            };
                        }
                        else
                        {
                            var candidate = new DiscoveredSecretCandidate(
                                PatternId: rule.PatternId,
                                SecretType: rule.SecretType,
                                Category: rule.Category,
                                RedactedValue: redacted,
                                SecretIdentityDigest: digest,
                                ShannonEntropy: entropy,
                                DiscoveredInAssetUrls: new[] { asset.CanonicalUrl },
                                OriginalSourceFiles: new[] { sourcePath },
                                UsageContext: usageContext,
                                Provenance: SourceProvenance.SourceMapOriginalSource,
                                Confidence: confidence,
                                BoundedSnippet: snippet,
                                LineNumber: GetLineNumber(sourceCode, match.Index),
                                ColumnNumber: GetColumnNumber(sourceCode, match.Index)
                            );

                            candidateMap[digest] = candidate;
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to parse source map JSON for asset '{Url}'.", asset.CanonicalUrl);
        }
    }

    private static AstUsageContext DetermineUsageContext(Program? program, string token, bool isTestAsset)
    {
        if (isTestAsset || KnownDummyTokens.Contains(token)) return AstUsageContext.TestOrExample;
        if (program == null) return AstUsageContext.StandaloneStringLiteral;

        foreach (var node in program.DescendantNodes())
        {
            if (node is Property prop && prop.Value is StringLiteral str && str.Value == token)
            {
                var keyName = prop.Key switch
                {
                    Identifier id => id.Name,
                    StringLiteral s => s.Value,
                    _ => string.Empty
                };

                if (keyName.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                    keyName.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                    keyName.Contains("key", StringComparison.OrdinalIgnoreCase) ||
                    keyName.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
                    keyName.Contains("password", StringComparison.OrdinalIgnoreCase))
                {
                    if (keyName.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                    {
                        return AstUsageContext.AuthHeader;
                    }
                    return AstUsageContext.ConfigObject;
                }
            }
            else if (node is NewExpression newExpr && newExpr.Arguments.Any(a => a is StringLiteral s && s.Value == token))
            {
                return AstUsageContext.ClientConstructorOption;
            }
        }

        return AstUsageContext.StandaloneStringLiteral;
    }

    private static FindingConfidence CalculateConfidence(
        SecretCategory category,
        string rawToken,
        double entropy,
        AstUsageContext usageContext,
        bool isTestAsset)
    {
        // 1. Explicit dummy/placeholder check
        if (KnownDummyTokens.Contains(rawToken) || isTestAsset || usageContext == AstUsageContext.TestOrExample)
        {
            return FindingConfidence.Low;
        }

        // 2. Private Key headers are inherently structural
        if (category == SecretCategory.PrivateKey)
        {
            return FindingConfidence.High;
        }

        // 3. Low entropy check for high-entropy token categories
        if (rawToken.Length >= 16 && entropy < 2.5)
        {
            return FindingConfidence.Low;
        }

        // 4. Context-elevated confidence
        if (usageContext is AstUsageContext.AuthHeader or AstUsageContext.ClientConstructorOption or AstUsageContext.ConfigObject)
        {
            return FindingConfidence.Medium;
        }

        return FindingConfidence.Low;
    }

    public static string RedactToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return string.Empty;
        if (token.Length <= 8) return new string('*', token.Length);

        // Preserve first 4 and last 4 characters
        return $"{token[..4]}...{token[^4..]}";
    }

    public static double CalculateShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;

        var map = new Dictionary<char, int>();
        foreach (char c in s)
        {
            map[c] = map.GetValueOrDefault(c, 0) + 1;
        }

        double entropy = 0;
        double len = s.Length;
        foreach (var count in map.Values)
        {
            double p = count / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static string ExtractBoundedRedactedSnippet(
        string fullCode,
        int matchIndex,
        int matchLength,
        string cleartextToken,
        string redactedToken)
    {
        if (string.IsNullOrWhiteSpace(fullCode)) return string.Empty;

        int start = Math.Max(0, matchIndex - 100);
        int end = Math.Min(fullCode.Length, matchIndex + matchLength + 100);
        int length = Math.Min(MaxSnippetLength, end - start);

        var snippet = fullCode.Substring(start, length);

        // Guarantee cleartext token is NEVER present in the snippet
        return snippet.Replace(cleartextToken, redactedToken, StringComparison.Ordinal);
    }

    private static bool IsTestOrMockAsset(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var lower = path.ToLowerInvariant();
        return lower.Contains(".test.") ||
               lower.Contains(".spec.") ||
               lower.Contains("/mocks/") ||
               lower.Contains("/fixtures/") ||
               lower.Contains("/test/") ||
               lower.Contains("/tests/");
    }

    private static string ComputeSha256(string raw)
    {
        var bytes = Encoding.UTF8.GetBytes(raw);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static int GetLineNumber(string text, int index)
    {
        if (index <= 0 || index >= text.Length) return 1;
        int line = 1;
        for (int i = 0; i < index; i++)
        {
            if (text[i] == '\n') line++;
        }
        return line;
    }

    private static int GetColumnNumber(string text, int index)
    {
        if (index <= 0 || index >= text.Length) return 1;
        int lastNewLine = text.LastIndexOf('\n', index - 1);
        return lastNewLine == -1 ? index + 1 : index - lastNewLine;
    }
}
