using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Validation;

public sealed record ProvenanceVerificationResult(
    bool IsVerified,
    string? ExpectedDigest,
    string? ResolvedDigest,
    string? ErrorMessage
);

/// <summary>
/// Authoritative supply chain verification service.
/// Resolves the actual immutable image manifest digest from the container registry
/// and verifies exact equality with the committed ScanToolManifest.ContainerImageDigest.
/// </summary>
public interface IToolProvenanceVerifier
{
    Task<ProvenanceVerificationResult> VerifyManifestDigestAsync(
        ScanToolManifest manifest,
        CancellationToken ct = default);
}
