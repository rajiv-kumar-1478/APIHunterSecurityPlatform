using System;
using System.Collections.Generic;
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
/// Authoritative output parser for Semgrep SAST scanner.
/// Transforms static source-code analysis receipts into FindingCandidate records and coverage metrics.
/// </summary>
public sealed class SemgrepOutputParser
{
    public const int MaxRawOutputBytes = 10 * 1024 * 1024; // 10 MiB
    public const int MaxCandidates = 1_000;
    public const int MaxEvidenceBytes = 16 * 1024;

    private readonly ILogger<SemgrepOutputParser> _logger;

    public SemgrepOutputParser(ILogger<SemgrepOutputParser> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<ToolParsedOutputResult> ParseAsync(
        ScanExecutionContext context,
        ToolExecutionRawOutput rawOutput,
        CancellationToken ct = default)
    {
        if (rawOutput == null || string.IsNullOrWhiteSpace(rawOutput.StandardOutput))
        {
            return Task.FromResult(new ToolParsedOutputResult(
                "semgrep",
                "1.172.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, false, null, 0, false)));
        }

        var rawBytes = Encoding.UTF8.GetByteCount(rawOutput.StandardOutput);
        if (rawBytes > MaxRawOutputBytes)
        {
            _logger.LogWarning("Semgrep raw output exceeded 10 MiB limit ({Bytes} bytes). Rejected to prevent DoS.", rawBytes);
            return Task.FromResult(new ToolParsedOutputResult(
                "semgrep",
                "1.172.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, true, "MaxRawOutputBytesExceeded", 0, true)));
        }

        var candidates = new List<FindingCandidate>();
        int filesScanned = 0;
        int malformedCount = 0;

        try
        {
            using var doc = JsonDocument.Parse(rawOutput.StandardOutput);
            var root = doc.RootElement;

            // 1. Extract Scanned Paths Coverage
            if (root.TryGetProperty("paths", out var pathsProp) &&
                pathsProp.TryGetProperty("scanned", out var scannedProp) &&
                scannedProp.ValueKind == JsonValueKind.Array)
            {
                filesScanned = scannedProp.GetArrayLength();
            }

            // 2. Parse SAST Results
            if (root.TryGetProperty("results", out var resultsProp) &&
                resultsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in resultsProp.EnumerateArray())
                {
                    if (candidates.Count >= MaxCandidates) break;

                    try
                    {
                        var checkId = item.TryGetProperty("check_id", out var idProp) ? idProp.GetString() ?? "semgrep.rule" : "semgrep.rule";
                        var path = item.TryGetProperty("path", out var pProp) ? pProp.GetString() ?? "unknown/file" : "unknown/file";

                        int line = 1;
                        if (item.TryGetProperty("start", out var startProp) &&
                            startProp.TryGetProperty("line", out var lineProp))
                        {
                            line = lineProp.GetInt32();
                        }

                        string message = checkId;
                        string rawSeverity = "medium";
                        string? cwe = null;
                        string? codeSnippet = null;

                        if (item.TryGetProperty("extra", out var extraProp))
                        {
                            if (extraProp.TryGetProperty("message", out var msgProp))
                            {
                                message = msgProp.GetString() ?? checkId;
                            }

                            if (extraProp.TryGetProperty("severity", out var sevProp))
                            {
                                var s = sevProp.GetString()?.ToUpperInvariant();
                                rawSeverity = s switch
                                {
                                    "ERROR" => "high",
                                    "WARNING" => "medium",
                                    "INFO" => "low",
                                    _ => "medium"
                                };
                            }

                            if (extraProp.TryGetProperty("metadata", out var metaProp))
                            {
                                if (metaProp.TryGetProperty("cwe", out var cweProp))
                                {
                                    if (cweProp.ValueKind == JsonValueKind.Array && cweProp.GetArrayLength() > 0)
                                    {
                                        cwe = ExtractCweId(cweProp[0].GetString());
                                    }
                                    else if (cweProp.ValueKind == JsonValueKind.String)
                                    {
                                        cwe = ExtractCweId(cweProp.GetString());
                                    }
                                }
                            }

                            if (extraProp.TryGetProperty("lines", out var linesProp))
                            {
                                codeSnippet = linesProp.GetString();
                            }
                        }

                        var rawItemJson = item.GetRawText();
                        if (rawItemJson.Length > MaxEvidenceBytes)
                        {
                            rawItemJson = rawItemJson[..MaxEvidenceBytes];
                        }

                        var targetUrl = context.TargetUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                            ? $"{context.TargetUrl.TrimEnd('/')}/{path.TrimStart('/')}"
                            : $"file://{path}";

                        var candidate = new FindingCandidate(
                            ToolKey: "semgrep",
                            ToolVersion: "1.172.0",
                            FindingType: FindingType.ProductionServiceExposed,
                            Title: FormatTitle(checkId, message),
                            Description: message,
                            RawSeverity: rawSeverity,
                            TargetUrl: targetUrl,
                            CweId: cwe,
                            EndpointPath: path,
                            HttpMethod: "STATIC_CODE",
                            ParameterName: $"Line:{line}",
                            RuleOrTemplateId: checkId,
                            RawEvidenceJson: rawItemJson,
                            ObservedAtUtc: DateTime.UtcNow
                        );

                        candidates.Add(candidate);
                    }
                    catch
                    {
                        malformedCount++;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse Semgrep JSON output.");
            malformedCount++;
        }

        var coverage = new ScannerCoverage(
            EndpointsDiscovered: filesScanned,
            ParametersExtracted: candidates.Count,
            AssetsProbed: filesScanned,
            JavaScriptFilesDiscovered: 0,
            CoverageTruncated: candidates.Count >= MaxCandidates,
            CoverageTruncationReason: candidates.Count >= MaxCandidates ? "MaxCandidatesLimitReached" : null,
            MalformedRecordCount: malformedCount,
            OutputTruncated: false
        );

        return Task.FromResult(new ToolParsedOutputResult(
            "semgrep",
            "1.172.0",
            candidates.AsReadOnly(),
            coverage
        ));
    }

    private static string? ExtractCweId(string? rawCwe)
    {
        if (string.IsNullOrWhiteSpace(rawCwe)) return null;

        var parts = rawCwe.Split(':');
        if (parts.Length > 0 && parts[0].Trim().StartsWith("CWE-", StringComparison.OrdinalIgnoreCase))
        {
            return parts[0].Trim();
        }

        return rawCwe.Trim();
    }

    private static string FormatTitle(string checkId, string message)
    {
        if (!string.IsNullOrWhiteSpace(message) && message.Length <= 80)
        {
            return message;
        }

        var lastDot = checkId.LastIndexOf('.');
        if (lastDot >= 0 && lastDot < checkId.Length - 1)
        {
            return checkId[(lastDot + 1)..].Replace('-', ' ').ToUpperInvariant();
        }

        return checkId;
    }
}
