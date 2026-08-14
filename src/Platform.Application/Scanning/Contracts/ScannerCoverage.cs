using System.Collections.Generic;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Bounded attack-surface coverage metrics emitted by a scanner adapter parser.
/// </summary>
public sealed record ScannerCoverage(
    int EndpointsDiscovered,
    int ParametersExtracted,
    int AssetsProbed,
    int JavaScriptFilesDiscovered,
    bool CoverageTruncated,
    string? CoverageTruncationReason = null,
    int MalformedRecordCount = 0,
    bool OutputTruncated = false,
    string? CoverageArtifactReference = null,
    IReadOnlyDictionary<string, object>? CoverageDetails = null
);
