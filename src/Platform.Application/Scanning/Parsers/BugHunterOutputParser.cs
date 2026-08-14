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
/// Authoritative output parser for BugHunter active contract and authorization verification scanner.
/// Transforms active probe receipts, BOLA detections, and parameter tampering results into FindingCandidate records.
/// </summary>
public sealed class BugHunterOutputParser
{
    public const int MaxRawOutputBytes = 10 * 1024 * 1024; // 10 MiB
    public const int MaxCandidates = 1_000;
    public const int MaxEvidenceBytes = 16 * 1024;

    private readonly ILogger<BugHunterOutputParser> _logger;

    public BugHunterOutputParser(ILogger<BugHunterOutputParser> logger)
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
                "bughunter",
                "2.1.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, false, null, 0, false));
        }

        var rawBytes = Encoding.UTF8.GetByteCount(rawOutput.StandardOutput);
        if (rawBytes > MaxRawOutputBytes)
        {
            _logger.LogWarning("BugHunter raw output exceeded 10 MiB limit ({Bytes} bytes). Rejected to prevent DoS.", rawBytes);
            return new ToolParsedOutputResult(
                "bughunter",
                "2.1.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, true, "MaxRawOutputBytesExceeded", 0, true));
        }

        var candidates = new List<FindingCandidate>();
        int malformedCount = 0;
        int endpointsTested = 0;
        int paramsTested = 0;

        using var reader = new StringReader(rawOutput.StandardOutput);
        string? line;

        while ((line = await reader.ReadLineAsync(ct)) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (candidates.Count >= MaxCandidates) break;

            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;

                var type = root.TryGetProperty("type", out var tProp) ? tProp.GetString() : "finding";

                if (type == "tested_metric")
                {
                    if (root.TryGetProperty("endpoints", out var eProp)) endpointsTested += eProp.GetInt32();
                    if (root.TryGetProperty("params", out var pProp)) paramsTested += pProp.GetInt32();
                    continue;
                }

                // Parse Finding Item
                var ruleId = root.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "bughunter-finding" : "bughunter-finding";
                var title = root.TryGetProperty("name", out var nProp) ? nProp.GetString() ?? "API Vulnerability" : "API Vulnerability";
                var severityStr = root.TryGetProperty("severity", out var sProp) ? sProp.GetString() ?? "medium" : "medium";
                var endpoint = root.TryGetProperty("endpoint", out var epProp) ? epProp.GetString() ?? context.TargetUrl : context.TargetUrl;
                var param = root.TryGetProperty("param", out var pmProp) ? pmProp.GetString() : null;
                var method = root.TryGetProperty("method", out var mProp) ? mProp.GetString() : "GET";
                var description = root.TryGetProperty("description", out var dProp) ? dProp.GetString() ?? title : title;
                var cwe = root.TryGetProperty("cwe", out var cweProp) ? cweProp.GetString() : null;

                var findingType = DetermineFindingType(ruleId, title);

                var rawEvidence = line.Length > MaxEvidenceBytes ? line[..MaxEvidenceBytes] : line;

                var candidate = new FindingCandidate(
                    ToolKey: "bughunter",
                    ToolVersion: "2.1.0",
                    FindingType: findingType,
                    Title: title,
                    Description: description,
                    RawSeverity: severityStr.ToLowerInvariant(),
                    TargetUrl: endpoint.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? endpoint : $"{context.TargetUrl.TrimEnd('/')}/{endpoint.TrimStart('/')}",
                    CweId: cwe,
                    EndpointPath: endpoint.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? new Uri(endpoint).AbsolutePath : endpoint,
                    HttpMethod: method,
                    ParameterName: param,
                    RuleOrTemplateId: ruleId,
                    RawEvidenceJson: rawEvidence,
                    ObservedAtUtc: DateTime.UtcNow
                );

                candidates.Add(candidate);
            }
            catch
            {
                malformedCount++;
            }
        }

        var coverage = new ScannerCoverage(
            EndpointsDiscovered: endpointsTested,
            ParametersExtracted: paramsTested,
            AssetsProbed: 1,
            JavaScriptFilesDiscovered: 0,
            CoverageTruncated: candidates.Count >= MaxCandidates,
            CoverageTruncationReason: candidates.Count >= MaxCandidates ? "MaxCandidatesLimitReached" : null,
            MalformedRecordCount: malformedCount,
            OutputTruncated: false
        );

        return new ToolParsedOutputResult(
            "bughunter",
            "2.1.0",
            candidates.AsReadOnly(),
            coverage
        );
    }

    private static FindingType DetermineFindingType(string ruleId, string title)
    {
        return FindingType.ProductionServiceExposed;
    }
}
