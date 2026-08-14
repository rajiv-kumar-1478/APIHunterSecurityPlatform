using System;
using System.Collections.Generic;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Maximum resource bounds applied to untrusted scanner outputs to prevent memory/CPU denial-of-service.
/// </summary>
public record ParserResourceBounds(
    int MaxRawOutputSizeBytes = 10 * 1024 * 1024,      // 10 MiB raw output limit
    int MaxSingleRecordSizeBytes = 64 * 1024,         // 64 KiB per candidate limit
    int MaxCandidateCount = 1000,                     // 1,000 candidates max per execution
    int MaxAttributesCount = 50,                      // Max 50 attributes per candidate
    int MaxAttributeValueLength = 1024,               // Max 1024 chars per attribute value
    int MaxEvidenceSizeBytes = 64 * 1024              // Max 64 KiB sanitized evidence payload
);

/// <summary>
/// Intermediate candidate representation extracted from untrusted scanner CLI outputs.
/// Scanner output is untrusted input: candidate properties are validated, sanitized, and normalized
/// by the platform ingestion engine before becoming authoritative SecurityFinding records.
/// </summary>
public record FindingCandidate(
    string ToolKey,
    string ToolVersion,
    FindingType FindingType,
    string Title,
    string Description,
    string RawSeverity,
    string TargetUrl,
    string? CveId = null,
    string? CWEId = null,
    string? CweId = null,
    string? TemplateId = null,
    string? EndpointPath = null,
    string? HttpMethod = null,
    int? HttpResponseStatusCode = null,
    string? ExtractedData = null,
    IReadOnlyDictionary<string, string>? Attributes = null,
    DateTime? ObservedAtUtc = null,
    string? ContainerImageRepository = null,
    string? ContainerImageDigest = null,
    string? Executable = null,
    string? ParameterName = null,
    string? VulnerableLocation = null,
    string? RuleOrTemplateId = null,
    string? RawEvidenceJson = null
);

/// <summary>
/// Contextual metadata for a running scan job used during candidate ingestion.
/// </summary>
public record ScanJobContext(
    Guid JobId,
    Guid RepositoryId,
    Guid TargetId,
    string TargetUrl,
    SecurityScanProfileType ScanProfile,
    DateTime JobStartedAtUtc
);

/// <summary>
/// Outcome metrics and diagnostics returned from candidate ingestion.
/// </summary>
public record FindingIngestionResult(
    int TotalCandidatesReceived,
    int CandidatesAccepted,
    int OutOfScopeDiscarded,
    int InvalidDiscarded,
    int NewFindingsCreated,
    int ExistingFindingsUpdated,
    IReadOnlyList<string> Diagnostics
);

/// <summary>
/// Contract for pure, format-specific tool output parsers.
/// Parsers map raw tool output into candidate records under strict resource bounds.
/// </summary>
public interface IToolOutputParser
{
    string ToolKey { get; }
    ToolOutputFormat SupportedFormat { get; }

    IReadOnlyList<FindingCandidate> Parse(
        string rawOutput,
        ScanJobContext context,
        ParserResourceBounds? bounds = null);
}
