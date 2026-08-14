using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Parsers;

/// <summary>
/// Authoritative output parser for JsMiner JavaScript crawler and static security analyzer.
/// Enforces strict resource bounds, input resilience, and discovery vs vulnerability separation.
/// </summary>
public sealed class JsMinerOutputParser
{
    public const int MaxRawOutputBytes = 10 * 1024 * 1024; // 10 MiB
    public const int MaxCandidates = 1_000;
    public const int MaxJavaScriptFiles = 500;
    public const int MaxEndpointsDiscovered = 5_000;
    public const int MaxParametersExtracted = 5_000;
    public const int MaxEvidenceBytes = 16 * 1024; // 16 KiB
    public const int MaxSnippetLength = 512;

    private readonly ILogger<JsMinerOutputParser> _logger;

    public JsMinerOutputParser(ILogger<JsMinerOutputParser> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<ToolParsedOutputResult> ParseAsync(
        ScanExecutionContext context,
        ToolExecutionRawOutput rawOutput,
        CancellationToken ct = default)
    {
        if (rawOutput == null || string.IsNullOrWhiteSpace(rawOutput.StandardOutput))
        {
            return new ToolParsedOutputResult(
                "jsminer",
                "1.2.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, false, null, 0, false));
        }

        var rawBytes = Encoding.UTF8.GetByteCount(rawOutput.StandardOutput);
        if (rawBytes > MaxRawOutputBytes)
        {
            _logger.LogWarning("JsMiner raw output exceeded 10 MiB limit ({Bytes} bytes). Output rejected to prevent DoS.", rawBytes);
            return new ToolParsedOutputResult(
                "jsminer",
                "1.2.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(
                    0, 0, 0, 0,
                    CoverageTruncated: true,
                    CoverageTruncationReason: "MaxRawOutputBytesExceeded",
                    MalformedRecordCount: 0,
                    OutputTruncated: true),
                ParseFailureReason: "MaxRawOutputBytesExceeded");
        }

        var candidates = new List<FindingCandidate>();
        var jsFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var parameters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenFindingKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        int malformedCount = 0;
        bool coverageTruncated = false;
        string? truncationReason = null;

        using var reader = new StringReader(rawOutput.StandardOutput);
        string? line;

        while ((line = await reader.ReadLineAsync(ct)) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var trimmedLine = line.Trim();
            if (trimmedLine.StartsWith("//") || trimmedLine.StartsWith("#")) continue;

            JsonDocument? doc = null;
            try
            {
                doc = JsonDocument.Parse(trimmedLine);
            }
            catch (JsonException)
            {
                malformedCount++;
                continue; // Do NOT abort - retain surrounding valid records
            }

            using (doc)
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    malformedCount++;
                    continue;
                }

                var recordType = GetStringProperty(root, "type", "kind", "recordType")?.ToLowerInvariant();

                switch (recordType)
                {
                    case "js_file":
                    case "script":
                    case "file":
                        ProcessJsFileRecord(root, jsFiles, ref coverageTruncated, ref truncationReason);
                        break;

                    case "endpoint":
                    case "route":
                    case "api":
                        ProcessEndpointRecord(root, endpoints, parameters, jsFiles, ref coverageTruncated, ref truncationReason);
                        break;

                    case "secret":
                    case "token":
                    case "credential":
                        ProcessSecretRecord(context, root, candidates, seenFindingKeys, ref coverageTruncated, ref truncationReason);
                        break;

                    case "dom_xss":
                    case "domxss":
                    case "sink":
                    case "dataflow":
                        ProcessDomXssRecord(context, root, candidates, seenFindingKeys, ref coverageTruncated, ref truncationReason);
                        break;

                    default:
                        // Generic discovery fallback: check for endpoints or secrets within object
                        if (root.TryGetProperty("endpoint", out _) || root.TryGetProperty("path", out _))
                        {
                            ProcessEndpointRecord(root, endpoints, parameters, jsFiles, ref coverageTruncated, ref truncationReason);
                        }
                        else if (root.TryGetProperty("secret", out _) || root.TryGetProperty("token", out _))
                        {
                            ProcessSecretRecord(context, root, candidates, seenFindingKeys, ref coverageTruncated, ref truncationReason);
                        }
                        else if (root.TryGetProperty("sink", out _) && root.TryGetProperty("source", out _))
                        {
                            ProcessDomXssRecord(context, root, candidates, seenFindingKeys, ref coverageTruncated, ref truncationReason);
                        }
                        else
                        {
                            malformedCount++;
                        }
                        break;
                }
            }
        }

        var coverage = new ScannerCoverage(
            EndpointsDiscovered: endpoints.Count,
            ParametersExtracted: parameters.Count,
            AssetsProbed: jsFiles.Count + endpoints.Count,
            JavaScriptFilesDiscovered: jsFiles.Count,
            CoverageTruncated: coverageTruncated,
            CoverageTruncationReason: truncationReason,
            MalformedRecordCount: malformedCount,
            OutputTruncated: false
        );

        return new ToolParsedOutputResult(
            "jsminer",
            "1.2.0",
            candidates.AsReadOnly(),
            coverage
        );
    }

    private static void ProcessJsFileRecord(
        JsonElement root,
        HashSet<string> jsFiles,
        ref bool coverageTruncated,
        ref string? truncationReason)
    {
        var fileUrl = GetStringProperty(root, "url", "file", "sourceUrl");
        if (!string.IsNullOrWhiteSpace(fileUrl))
        {
            if (jsFiles.Count < MaxJavaScriptFiles)
            {
                jsFiles.Add(fileUrl.Trim());
            }
            else if (!coverageTruncated)
            {
                coverageTruncated = true;
                truncationReason = nameof(MaxJavaScriptFiles);
            }
        }
    }

    private static void ProcessEndpointRecord(
        JsonElement root,
        HashSet<string> endpoints,
        HashSet<string> parameters,
        HashSet<string> jsFiles,
        ref bool coverageTruncated,
        ref string? truncationReason)
    {
        var url = GetStringProperty(root, "url", "endpoint", "path");
        var method = GetStringProperty(root, "method") ?? "GET";
        var sourceUrl = GetStringProperty(root, "sourceJsUrl", "sourceUrl", "file");

        if (!string.IsNullOrWhiteSpace(sourceUrl) && jsFiles.Count < MaxJavaScriptFiles)
        {
            jsFiles.Add(sourceUrl.Trim());
        }

        if (!string.IsNullOrWhiteSpace(url))
        {
            var endpointKey = $"{method.ToUpperInvariant()} {url.Trim()}";
            if (endpoints.Count < MaxEndpointsDiscovered)
            {
                endpoints.Add(endpointKey);
            }
            else if (!coverageTruncated)
            {
                coverageTruncated = true;
                truncationReason = nameof(MaxEndpointsDiscovered);
            }
        }

        if (root.TryGetProperty("params", out var paramsProp) || root.TryGetProperty("parameters", out paramsProp))
        {
            if (paramsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var paramElem in paramsProp.EnumerateArray())
                {
                    var paramName = paramElem.GetString();
                    if (!string.IsNullOrWhiteSpace(paramName))
                    {
                        if (parameters.Count < MaxParametersExtracted)
                        {
                            parameters.Add(paramName.Trim());
                        }
                        else if (!coverageTruncated)
                        {
                            coverageTruncated = true;
                            truncationReason = nameof(MaxParametersExtracted);
                        }
                    }
                }
            }
        }
    }

    private static void ProcessSecretRecord(
        ScanExecutionContext context,
        JsonElement root,
        List<FindingCandidate> candidates,
        HashSet<string> seenFindingKeys,
        ref bool coverageTruncated,
        ref string? truncationReason)
    {
        if (candidates.Count >= MaxCandidates)
        {
            if (!coverageTruncated)
            {
                coverageTruncated = true;
                truncationReason = nameof(MaxCandidates);
            }
            return;
        }

        var patternId = GetStringProperty(root, "patternId", "ruleId", "rule") ?? "js-secret-token";
        var secretType = GetStringProperty(root, "secretType", "type", "category") ?? "generic-secret";
        var sourceJsUrl = GetStringProperty(root, "sourceJsUrl", "sourceUrl", "file", "url") ?? context.TargetUrl;
        var line = GetIntProperty(root, "line") ?? 1;
        var column = GetIntProperty(root, "column") ?? 1;
        var snippet = TruncateSnippet(GetStringProperty(root, "snippet", "match", "context"));

        // Deduplication key
        var dedupKey = $"{sourceJsUrl}:{patternId}:{line}:{column}";
        if (seenFindingKeys.Contains(dedupKey)) return;
        seenFindingKeys.Add(dedupKey);

        var evidenceDict = new Dictionary<string, object?>
        {
            ["discoverySource"] = "jsminer",
            ["patternId"] = patternId,
            ["secretType"] = secretType,
            ["sourceJsUrl"] = sourceJsUrl,
            ["line"] = line,
            ["column"] = column,
            ["codeSnippet"] = snippet
        };

        var rawEvidenceJson = TruncateJson(JsonSerializer.Serialize(evidenceDict));

        var candidate = new FindingCandidate(
            ToolKey: "jsminer",
            ToolVersion: "1.2.0",
            FindingType: FindingType.UnvalidatedCredentialExposed,
            Title: $"Possible Exposed Secret: {secretType}",
            Description: $"JsMiner identified unvalidated secret pattern '{patternId}' in JavaScript asset.",
            RawSeverity: "medium",
            TargetUrl: sourceJsUrl,
            ExtractedData: snippet,
            Attributes: new Dictionary<string, string>
            {
                ["scanner"] = "jsminer",
                ["pattern"] = patternId,
                ["source"] = sourceJsUrl,
                ["line"] = line.ToString(),
                ["column"] = column.ToString()
            },
            ParameterName: null,
            VulnerableLocation: $"{sourceJsUrl}:{line}:{column}",
            RuleOrTemplateId: patternId,
            RawEvidenceJson: rawEvidenceJson
        );

        candidates.Add(candidate);
    }

    private static void ProcessDomXssRecord(
        ScanExecutionContext context,
        JsonElement root,
        List<FindingCandidate> candidates,
        HashSet<string> seenFindingKeys,
        ref bool coverageTruncated,
        ref string? truncationReason)
    {
        if (candidates.Count >= MaxCandidates)
        {
            if (!coverageTruncated)
            {
                coverageTruncated = true;
                truncationReason = nameof(MaxCandidates);
            }
            return;
        }

        var source = GetStringProperty(root, "source", "sourceType") ?? "unknown-source";
        var sink = GetStringProperty(root, "sink", "sinkType") ?? "unknown-sink";
        var sourceJsUrl = GetStringProperty(root, "sourceJsUrl", "sourceUrl", "file", "url") ?? context.TargetUrl;
        var line = GetIntProperty(root, "line") ?? 1;
        var column = GetIntProperty(root, "column") ?? 1;
        var snippet = TruncateSnippet(GetStringProperty(root, "snippet", "code", "context"));

        // Deduplication key
        var dedupKey = $"{sourceJsUrl}:{source}->{sink}:{line}:{column}";
        if (seenFindingKeys.Contains(dedupKey)) return;
        seenFindingKeys.Add(dedupKey);

        var evidenceDict = new Dictionary<string, object?>
        {
            ["discoverySource"] = "jsminer",
            ["flowType"] = "dom-xss-potential",
            ["source"] = source,
            ["sink"] = sink,
            ["sourceJsUrl"] = sourceJsUrl,
            ["line"] = line,
            ["column"] = column,
            ["codeSnippet"] = snippet
        };

        var rawEvidenceJson = TruncateJson(JsonSerializer.Serialize(evidenceDict));

        var candidate = new FindingCandidate(
            ToolKey: "jsminer",
            ToolVersion: "1.2.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: $"Potential DOM XSS Data Flow: {source} -> {sink}",
            Description: $"JsMiner identified potential client-side data flow from tainted source '{source}' to sink '{sink}'.",
            RawSeverity: "low",
            TargetUrl: sourceJsUrl,
            ExtractedData: snippet,
            Attributes: new Dictionary<string, string>
            {
                ["scanner"] = "jsminer",
                ["flowType"] = "dom-xss-potential",
                ["source"] = source,
                ["sink"] = sink,
                ["line"] = line.ToString(),
                ["column"] = column.ToString()
            },
            ParameterName: source,
            VulnerableLocation: $"{sourceJsUrl}:{line}:{column}",
            RuleOrTemplateId: "dom-xss-potential",
            RawEvidenceJson: rawEvidenceJson
        );

        candidates.Add(candidate);
    }

    private static string? TruncateSnippet(string? snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet)) return snippet;
        var trimmed = snippet.Trim();
        if (trimmed.Length <= MaxSnippetLength) return trimmed;
        return trimmed.Substring(0, MaxSnippetLength - 3) + "...";
    }

    private static string TruncateJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return "{}";
        var bytes = Encoding.UTF8.GetByteCount(json);
        if (bytes <= MaxEvidenceBytes) return json;
        return json.Substring(0, MaxEvidenceBytes - 3) + "...";
    }

    private static string? GetStringProperty(JsonElement element, params string[] propertyNames)
    {
        foreach (var prop in propertyNames)
        {
            if (element.TryGetProperty(prop, out var val) && val.ValueKind == JsonValueKind.String)
            {
                return val.GetString();
            }
        }
        return null;
    }

    private static int? GetIntProperty(JsonElement element, params string[] propertyNames)
    {
        foreach (var prop in propertyNames)
        {
            if (element.TryGetProperty(prop, out var val) && val.ValueKind == JsonValueKind.Number && val.TryGetInt32(out var i))
            {
                return i;
            }
        }
        return null;
    }
}
