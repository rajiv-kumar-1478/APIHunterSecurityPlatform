using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Parsers;

/// <summary>
/// Parser for ProjectDiscovery httpx HTTP probing tool output (JSON & JSON Lines).
/// Extracts exposed endpoints, status codes, and technology fingerprints into normalized FindingCandidate objects.
/// </summary>
public class HttpxOutputParser : IToolOutputParser
{
    public string ToolKey => "httpx";
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

        if (rawOutput.Length > activeBounds.MaxRawOutputSizeBytes)
        {
            rawOutput = rawOutput.Substring(0, activeBounds.MaxRawOutputSizeBytes);
        }

        var trimmed = rawOutput.Trim();

        // 1. JSON Array format
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

                        var candidate = ParseHttpxElement(element, context);
                        if (candidate != null)
                        {
                            candidates.Add(candidate);
                        }
                    }
                }
            }
            catch (JsonException)
            {
            }

            return candidates;
        }

        // 2. JSON Lines format
        using var reader = new StringReader(trimmed);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (candidates.Count >= activeBounds.MaxCandidateCount) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                using var lineDoc = JsonDocument.Parse(line.Trim());
                var candidate = ParseHttpxElement(lineDoc.RootElement, context);
                if (candidate != null)
                {
                    candidates.Add(candidate);
                }
            }
            catch (JsonException)
            {
            }
        }

        return candidates;
    }

    private static FindingCandidate? ParseHttpxElement(JsonElement root, ScanJobContext context)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() : null;
        url ??= root.TryGetProperty("input", out var inputProp) ? inputProp.GetString() : null;

        if (string.IsNullOrWhiteSpace(url)) return null;

        var pageTitle = root.TryGetProperty("title", out var titleProp) ? titleProp.GetString() : null;
        var statusCode = root.TryGetProperty("status_code", out var scProp) && scProp.TryGetInt32(out var sc) ? sc : (int?)null;
        var webserver = root.TryGetProperty("webserver", out var wsProp) ? wsProp.GetString() : null;
        var method = root.TryGetProperty("method", out var methProp) ? methProp.GetString() : "GET";
        var path = root.TryGetProperty("path", out var pathProp) ? pathProp.GetString() : null;

        var techList = new List<string>();
        if (root.TryGetProperty("tech", out var techProp) && techProp.ValueKind == JsonValueKind.Array)
        {
            techList = techProp.EnumerateArray()
                .Where(t => t.ValueKind == JsonValueKind.String)
                .Select(t => t.GetString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToList()!;
        }

        var candidateTitle = !string.IsNullOrWhiteSpace(pageTitle)
            ? $"HTTP Service: {pageTitle} ({url})"
            : $"HTTP Service Discovered ({url})";

        var description = $"HTTP endpoint probed successfully with status code {statusCode ?? 200}.";
        if (techList.Count > 0)
        {
            description += $" Detected technologies: {string.Join(", ", techList)}.";
        }
        if (!string.IsNullOrWhiteSpace(webserver))
        {
            description += $" Web server: {webserver}.";
        }

        var attributes = new Dictionary<string, string>();
        if (statusCode.HasValue) attributes["status_code"] = statusCode.Value.ToString();
        if (!string.IsNullOrWhiteSpace(webserver)) attributes["webserver"] = webserver;
        if (techList.Count > 0) attributes["technologies"] = string.Join(", ", techList);

        return new FindingCandidate(
            ToolKey: "httpx",
            ToolVersion: "v1.4.0",
            FindingType: FindingType.ProductionServiceExposed,
            Title: candidateTitle,
            Description: description,
            RawSeverity: "info",
            TargetUrl: url,
            TemplateId: "httpx-service-discovery",
            EndpointPath: path,
            HttpMethod: method,
            HttpResponseStatusCode: statusCode,
            ExtractedData: techList.Count > 0 ? string.Join(", ", techList) : webserver,
            Attributes: attributes,
            ObservedAtUtc: DateTime.UtcNow
        );
    }
}
