using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Parsers;

/// <summary>
/// Parser for ProjectDiscovery Nuclei vulnerability scanner output (JSON & JSON Lines).
/// Parses untrusted output into normalized FindingCandidate objects under strict resource bounds.
/// </summary>
public class NucleiOutputParser : IToolOutputParser
{
    public string ToolKey => "nuclei";
    public ToolOutputFormat SupportedFormat => ToolOutputFormat.JsonLines;

    public IReadOnlyList<FindingCandidate> Parse(
        string rawOutput,
        ScanJobContext context,
        ParserResourceBounds? bounds = null)
    {
        var activeBounds = bounds ?? new ParserResourceBounds();
        var candidates = new List<FindingCandidate>();

        if (string.IsNullOrWhiteSpace(rawOutput))
        {
            return candidates;
        }

        // Bounded raw output check
        if (rawOutput.Length > activeBounds.MaxRawOutputSizeBytes)
        {
            rawOutput = rawOutput.Substring(0, activeBounds.MaxRawOutputSizeBytes);
        }

        var trimmed = rawOutput.Trim();

        // 1. JSON Array format: starts with '['
        if (trimmed.StartsWith("["))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var element in doc.RootElement.EnumerateArray())
                    {
                        if (candidates.Count >= activeBounds.MaxCandidateCount) break;

                        var candidate = ParseNucleiElement(element, context);
                        if (candidate != null)
                        {
                            candidates.Add(candidate);
                        }
                    }
                }
            }
            catch (JsonException)
            {
                // Graceful fallback for malformed JSON payload
            }

            return candidates;
        }

        // 2. JSON Lines format: one JSON object per line
        using var reader = new StringReader(trimmed);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (candidates.Count >= activeBounds.MaxCandidateCount) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                using var lineDoc = JsonDocument.Parse(line.Trim());
                var candidate = ParseNucleiElement(lineDoc.RootElement, context);
                if (candidate != null)
                {
                    candidates.Add(candidate);
                }
            }
            catch (JsonException)
            {
                // Ignore individual malformed lines gracefully
            }
        }

        return candidates;
    }

    private static FindingCandidate? ParseNucleiElement(JsonElement root, ScanJobContext context)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;

        // Extract template-id
        var templateId = root.TryGetProperty("template-id", out var tIdProp) ? tIdProp.GetString() : null;
        templateId ??= root.TryGetProperty("templateID", out var tIdProp2) ? tIdProp2.GetString() : "unknown-template";

        // Extract info block
        var title = templateId;
        var description = string.Empty;
        var rawSeverity = "info";
        string? cveId = null;
        string? cweId = null;

        if (root.TryGetProperty("info", out var info) && info.ValueKind == JsonValueKind.Object)
        {
            if (info.TryGetProperty("name", out var nameProp) && !string.IsNullOrWhiteSpace(nameProp.GetString()))
            {
                title = nameProp.GetString()!;
            }

            if (info.TryGetProperty("description", out var descProp))
            {
                description = descProp.GetString() ?? string.Empty;
            }

            if (info.TryGetProperty("severity", out var sevProp))
            {
                rawSeverity = sevProp.GetString() ?? "info";
            }

            if (info.TryGetProperty("classification", out var classProp) && classProp.ValueKind == JsonValueKind.Object)
            {
                cveId = ExtractFirstStringOrArrayElement(classProp, "cve-id");
                cweId = ExtractFirstStringOrArrayElement(classProp, "cwe-id");
            }
        }

        // Extract target URL / matched-at
        var targetUrl = root.TryGetProperty("matched-at", out var matchedProp) ? matchedProp.GetString() : null;
        targetUrl ??= root.TryGetProperty("matched", out var matchedProp2) ? matchedProp2.GetString() : null;
        targetUrl ??= root.TryGetProperty("host", out var hostProp) ? hostProp.GetString() : context.TargetUrl;

        if (string.IsNullOrWhiteSpace(targetUrl))
        {
            targetUrl = context.TargetUrl;
        }

        // Extract path & HTTP info if available
        string? path = null;
        if (root.TryGetProperty("path", out var pathProp))
        {
            path = pathProp.GetString();
        }

        string? extractedData = null;
        if (root.TryGetProperty("extracted-results", out var extProp) && extProp.ValueKind == JsonValueKind.Array)
        {
            var results = extProp.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToList();

            if (results.Count > 0)
            {
                extractedData = string.Join("; ", results);
            }
        }

        // Extract timestamp
        DateTime? observedAt = null;
        if (root.TryGetProperty("timestamp", out var tsProp) && tsProp.TryGetDateTime(out var parsedTs))
        {
            observedAt = parsedTs.ToUniversalTime();
        }

        var attributes = new Dictionary<string, string>();
        if (root.TryGetProperty("type", out var typeProp) && !string.IsNullOrWhiteSpace(typeProp.GetString()))
        {
            attributes["protocol_type"] = typeProp.GetString()!;
        }
        if (root.TryGetProperty("matcher-name", out var matcherProp) && !string.IsNullOrWhiteSpace(matcherProp.GetString()))
        {
            attributes["matcher_name"] = matcherProp.GetString()!;
        }

        return new FindingCandidate(
            ToolKey: "nuclei",
            ToolVersion: "v3.1.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: !string.IsNullOrWhiteSpace(title) ? title : (templateId ?? "nuclei-finding"),
            Description: description,
            RawSeverity: rawSeverity,
            TargetUrl: targetUrl,
            CveId: cveId,
            CweId: cweId,
            TemplateId: templateId,
            EndpointPath: path,
            ExtractedData: extractedData,
            Attributes: attributes,
            ObservedAtUtc: observedAt
        );
    }

    private static string? ExtractFirstStringOrArrayElement(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var prop)) return null;

        if (prop.ValueKind == JsonValueKind.String)
        {
            return prop.GetString();
        }

        if (prop.ValueKind == JsonValueKind.Array)
        {
            var first = prop.EnumerateArray().FirstOrDefault();
            if (first.ValueKind == JsonValueKind.String)
            {
                return first.GetString();
            }
        }

        return null;
    }
}
