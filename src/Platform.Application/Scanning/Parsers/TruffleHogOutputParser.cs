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
/// Authoritative output parser for TruffleHog secret scanner (v3.96.0+).
/// Parses JSON Lines and JSON array outputs under strict resource bounds and enforces
/// fail-closed zero raw secret persistence (Raw / RawV2 are strictly discarded).
/// </summary>
public sealed class TruffleHogOutputParser
{
    public const int MaxRawOutputBytes = 10 * 1024 * 1024; // 10 MiB
    public const int MaxCandidates = 1_000;
    public const int MaxEvidenceBytes = 16 * 1024;

    private static readonly HashSet<string> AllowedExtraDataKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "rotation_guide", "version", "account", "user", "service", "region", "arn", "email"
    };

    private readonly ILogger<TruffleHogOutputParser> _logger;

    public TruffleHogOutputParser(ILogger<TruffleHogOutputParser> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<ToolParsedOutputResult> ParseAsync(
        ScanExecutionContext context,
        ToolExecutionRawOutput rawOutput,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (rawOutput == null || string.IsNullOrWhiteSpace(rawOutput.StandardOutput))
        {
            return Task.FromResult(new ToolParsedOutputResult(
                "trufflehog",
                "3.96.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, false, null, 0, false)));
        }

        var rawBytes = Encoding.UTF8.GetByteCount(rawOutput.StandardOutput);
        if (rawBytes > MaxRawOutputBytes)
        {
            _logger.LogWarning("TruffleHog raw output exceeded 10 MiB limit ({Bytes} bytes). Rejected to prevent DoS.", rawBytes);
            return Task.FromResult(new ToolParsedOutputResult(
                "trufflehog",
                "3.96.0",
                Array.Empty<FindingCandidate>(),
                new ScannerCoverage(0, 0, 0, 0, true, "MaxRawOutputBytesExceeded", 0, true)));
        }

        var candidates = new List<FindingCandidate>();
        var scannedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int malformedCount = 0;
        var trimmed = rawOutput.StandardOutput.Trim();

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
                        if (candidates.Count >= MaxCandidates) break;

                        var candidate = ParseFindingElement(element, context, scannedFiles);
                        if (candidate != null)
                        {
                            candidates.Add(candidate);
                        }
                        else
                        {
                            malformedCount++;
                        }
                    }
                }
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "TruffleHog output contained malformed JSON array payload.");
                malformedCount++;
            }
        }
        else
        {
            // 2. JSON Lines format: one JSON object per line
            using var reader = new StringReader(trimmed);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (candidates.Count >= MaxCandidates) break;
                if (string.IsNullOrWhiteSpace(line)) continue;

                try
                {
                    using var lineDoc = JsonDocument.Parse(line.Trim());
                    var candidate = ParseFindingElement(lineDoc.RootElement, context, scannedFiles);
                    if (candidate != null)
                    {
                        candidates.Add(candidate);
                    }
                    else
                    {
                        malformedCount++;
                    }
                }
                catch (JsonException)
                {
                    // Ignore and record malformed line gracefully
                    malformedCount++;
                }
            }
        }

        var coverage = new ScannerCoverage(
            EndpointsDiscovered: 0,
            ParametersExtracted: 0,
            AssetsProbed: scannedFiles.Count,
            JavaScriptFilesDiscovered: 0,
            CoverageTruncated: candidates.Count >= MaxCandidates,
            CoverageTruncationReason: candidates.Count >= MaxCandidates ? "MaxCandidateCountReached" : null,
            MalformedRecordCount: malformedCount,
            OutputTruncated: false
        );

        return Task.FromResult(new ToolParsedOutputResult(
            "trufflehog",
            "3.96.0",
            candidates.AsReadOnly(),
            coverage
        ));
    }

    private static FindingCandidate? ParseFindingElement(
        JsonElement root,
        ScanExecutionContext context,
        HashSet<string> scannedFiles)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;

        // Detector info
        var detectorName = root.TryGetProperty("DetectorName", out var dNameProp) ? dNameProp.GetString() : null;
        detectorName ??= root.TryGetProperty("detector_name", out var dNameProp2) ? dNameProp2.GetString() : "GenericSecret";

        var detectorDescription = root.TryGetProperty("DetectorDescription", out var dDescProp) ? dDescProp.GetString() : null;
        detectorDescription ??= root.TryGetProperty("detector_description", out var dDescProp2) ? dDescProp2.GetString() : $"TruffleHog detected potential {detectorName} credential exposure.";

        int detectorType = 0;
        if (root.TryGetProperty("DetectorType", out var dTypeProp) && dTypeProp.TryGetInt32(out var dt))
        {
            detectorType = dt;
        }

        // Verified status
        bool verified = false;
        if (root.TryGetProperty("Verified", out var vProp))
        {
            verified = vProp.ValueKind == JsonValueKind.True;
        }
        else if (root.TryGetProperty("verified", out var vProp2))
        {
            verified = vProp2.ValueKind == JsonValueKind.True;
        }

        // Source metadata extraction (filesystem / git / etc.)
        string filePath = "unknown";
        int line = 1;
        string? commit = null;

        if (root.TryGetProperty("SourceMetadata", out var smProp) && smProp.ValueKind == JsonValueKind.Object)
        {
            if (smProp.TryGetProperty("Data", out var dataProp) && dataProp.ValueKind == JsonValueKind.Object)
            {
                if (dataProp.TryGetProperty("Filesystem", out var fsProp) && fsProp.ValueKind == JsonValueKind.Object)
                {
                    if (fsProp.TryGetProperty("file", out var fileProp) && !string.IsNullOrWhiteSpace(fileProp.GetString()))
                    {
                        filePath = fileProp.GetString()!;
                        scannedFiles.Add(filePath);
                    }
                    if (fsProp.TryGetProperty("line", out var lineProp) && lineProp.TryGetInt32(out var l))
                    {
                        line = l;
                    }
                }
                else if (dataProp.TryGetProperty("Git", out var gitProp) && gitProp.ValueKind == JsonValueKind.Object)
                {
                    if (gitProp.TryGetProperty("file", out var gFileProp) && !string.IsNullOrWhiteSpace(gFileProp.GetString()))
                    {
                        filePath = gFileProp.GetString()!;
                        scannedFiles.Add(filePath);
                    }
                    if (gitProp.TryGetProperty("line", out var gLineProp) && gLineProp.TryGetInt32(out var gl))
                    {
                        line = gl;
                    }
                    if (gitProp.TryGetProperty("commit", out var commitProp))
                    {
                        commit = commitProp.GetString();
                    }
                }
            }
        }

        // Zero Raw Secret Storage Policy:
        // Raw and RawV2 are NEVER persisted.
        // Only safely redacted string is stored in ExtractedData.
        string redacted = $"[REDACTED {detectorName} SECRET]";
        if (root.TryGetProperty("Redacted", out var redProp) && !string.IsNullOrWhiteSpace(redProp.GetString()))
        {
            var rawRedacted = redProp.GetString()!;
            redacted = rawRedacted.Length > 256 ? rawRedacted.Substring(0, 256) : rawRedacted;
        }
        else if (root.TryGetProperty("redacted", out var redProp2) && !string.IsNullOrWhiteSpace(redProp2.GetString()))
        {
            var rawRedacted = redProp2.GetString()!;
            redacted = rawRedacted.Length > 256 ? rawRedacted.Substring(0, 256) : rawRedacted;
        }

        // Calibrated Platform Severity & FindingType
        var findingType = verified
            ? FindingType.ValidatedCredentialExposed
            : FindingType.UnvalidatedCredentialExposed;

        var rawSeverity = verified ? "critical" : "medium";

        // Attributes (allowlisted, non-sensitive)
        var attributes = new Dictionary<string, string>
        {
            ["detector_name"] = detectorName ?? "GenericSecret",
            ["detector_type"] = detectorType.ToString(),
            ["verified"] = verified ? "true" : "false",
            ["file_path"] = filePath,
            ["line_number"] = line.ToString()
        };

        if (!string.IsNullOrWhiteSpace(commit))
        {
            attributes["git_commit"] = commit;
        }

        if (root.TryGetProperty("ExtraData", out var extraProp) && extraProp.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in extraProp.EnumerateObject())
            {
                if (AllowedExtraDataKeys.Contains(prop.Name) && prop.Value.ValueKind == JsonValueKind.String)
                {
                    var val = prop.Value.GetString();
                    if (!string.IsNullOrWhiteSpace(val))
                    {
                        attributes[$"extra_{prop.Name.ToLowerInvariant()}"] = val.Length > 256 ? val.Substring(0, 256) : val;
                    }
                }
            }
        }

        var vulnerableLocation = $"{filePath}:{line}";
        var title = verified
            ? $"Exposed & Validated {detectorName} Secret"
            : $"Exposed {detectorName} Credential Candidate";

        return new FindingCandidate(
            ToolKey: "trufflehog",
            ToolVersion: "3.96.0",
            FindingType: findingType,
            Title: title,
            Description: detectorDescription ?? "TruffleHog detected potential credential exposure.",
            RawSeverity: rawSeverity,
            TargetUrl: !string.IsNullOrWhiteSpace(context.TargetUrl) ? context.TargetUrl : filePath,
            TemplateId: detectorName,
            RuleOrTemplateId: detectorName,
            EndpointPath: filePath,
            VulnerableLocation: vulnerableLocation,
            ExtractedData: redacted,
            Attributes: attributes,
            ObservedAtUtc: DateTime.UtcNow
        );
    }
}
