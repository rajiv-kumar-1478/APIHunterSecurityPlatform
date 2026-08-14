using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Services;

/// <summary>
/// Authoritative platform service for computing canonical, deterministic finding fingerprints.
/// Governs deduplication, lifecycle progression, and cross-scanner finding correlation.
/// </summary>
public interface IFindingFingerprintService
{
    /// <summary>
    /// Computes the 64-character lowercase SHA-256 canonical v1 fingerprint from candidate components.
    /// </summary>
    string ComputeCanonicalFingerprint(
        string targetUrl,
        string findingType,
        string? httpMethod = null,
        string? parameterName = null,
        string? vulnerableLocation = null,
        string? ruleOrTemplateId = null);

    /// <summary>
    /// Computes the canonical v1 fingerprint for a normalized FindingCandidate.
    /// </summary>
    string ComputeCanonicalFingerprint(FindingCandidate candidate);
}
