using System;
using System.Collections.Generic;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.JavaScript.Contracts;

public enum SecretCategory
{
    CloudCredential = 1,
    ApiKey = 2,
    OAuthToken = 3,
    PrivateKey = 4,
    DatabaseUri = 5,
    InternalInfrastructure = 6
}

public enum AstUsageContext
{
    AuthHeader = 1,
    ClientConstructorOption = 2,
    ConfigObject = 3,
    VariableDeclaration = 4,
    StandaloneStringLiteral = 5,
    CommentOrDoc = 6,
    TestOrExample = 7
}

public enum SourceProvenance
{
    ProductionBundle = 1,
    SourceMapOriginalSource = 2,
    InlineScript = 3
}

/// <summary>
/// Internal intermediate representation of a detected sensitive value before candidate generation.
/// Cleartext values are strictly kept in memory during analysis and never persisted or exported.
/// </summary>
public sealed record DiscoveredSecretCandidate(
    string PatternId,
    string SecretType,
    SecretCategory Category,
    string RedactedValue,
    string SecretIdentityDigest,
    double ShannonEntropy,
    IReadOnlyList<string> DiscoveredInAssetUrls,
    IReadOnlyList<string>? OriginalSourceFiles,
    AstUsageContext UsageContext,
    SourceProvenance Provenance,
    FindingConfidence Confidence,
    string BoundedSnippet,
    int LineNumber,
    int ColumnNumber
);

/// <summary>
/// Result of JavaScript sensitive-value analysis, separating credential finding candidates
/// from internal infrastructure discovery facts.
/// </summary>
public sealed record JsSecretAnalysisResult(
    IReadOnlyList<FindingCandidate> FindingCandidates,
    IReadOnlyList<string> DiscoveredInternalHosts,
    int TotalSecretsDetected,
    int DeduplicatedSecretsCount,
    DateTime GeneratedAtUtc
);
