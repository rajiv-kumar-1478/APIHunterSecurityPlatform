using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Parsers;

/// <summary>
/// Parser for ProjectDiscovery Subfinder passive subdomain enumeration tool output (JSON, JSONL, and line-delimited hostnames).
/// </summary>
public class SubfinderOutputParser : IToolOutputParser
{
    public string ToolKey => "subfinder";
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

                        var candidate = ParseSubfinderJsonElement(element, context);
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

        // 2. Line-by-line reading (handles JSON Lines and plain hostname lines)
        using var reader = new StringReader(trimmed);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (candidates.Count >= activeBounds.MaxCandidateCount) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            var trimmedLine = line.Trim();

            // Try JSON object first
            if (trimmedLine.StartsWith("{") && trimmedLine.EndsWith("}"))
            {
                try
                {
                    using var lineDoc = JsonDocument.Parse(trimmedLine);
                    var candidate = ParseSubfinderJsonElement(lineDoc.RootElement, context);
                    if (candidate != null)
                    {
                        candidates.Add(candidate);
                        continue;
                    }
                }
                catch (JsonException)
                {
                }
            }

            // Fallback: Plaintext hostname line
            if (!trimmedLine.Contains(" ") && trimmedLine.Contains("."))
            {
                var candidate = CreateSubdomainCandidate(trimmedLine, "line_output", context);
                candidates.Add(candidate);
            }
        }

        return candidates;
    }

    private static FindingCandidate? ParseSubfinderJsonElement(JsonElement root, ScanJobContext context)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;

        var host = root.TryGetProperty("host", out var hostProp) ? hostProp.GetString() : null;
        host ??= root.TryGetProperty("subdomain", out var subProp) ? subProp.GetString() : null;

        if (string.IsNullOrWhiteSpace(host)) return null;

        var source = root.TryGetProperty("source", out var srcProp) ? srcProp.GetString() : "passive_enumeration";

        return CreateSubdomainCandidate(host.Trim(), source ?? "passive_enumeration", context);
    }

    private static FindingCandidate CreateSubdomainCandidate(string host, string source, ScanJobContext context)
    {
        var targetUrl = host.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? host
            : $"https://{host}";

        var attributes = new Dictionary<string, string>
        {
            ["source"] = source,
            ["discovered_host"] = host
        };

        return new FindingCandidate(
            ToolKey: "subfinder",
            ToolVersion: "v2.6.6",
            FindingType: FindingType.ProductionServiceExposed,
            Title: $"Subdomain Discovered: {host}",
            Description: $"Passive subdomain enumeration discovered host '{host}' via source '{source}'.",
            RawSeverity: "info",
            TargetUrl: targetUrl,
            TemplateId: "subfinder-subdomain-discovery",
            ExtractedData: $"Host: {host}, Source: {source}",
            Attributes: attributes,
            ObservedAtUtc: DateTime.UtcNow
        );
    }
}
