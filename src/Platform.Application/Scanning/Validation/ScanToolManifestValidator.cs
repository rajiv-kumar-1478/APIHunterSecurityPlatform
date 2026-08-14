using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Validation;

public sealed record ManifestValidationResult(
    bool IsValid,
    IReadOnlyList<string> Errors
);

/// <summary>
/// Authoritative validator for immutable ScanToolManifest software supply chain definitions.
/// </summary>
public static class ScanToolManifestValidator
{
    private static readonly Regex ToolKeyRegex = new(@"^[a-z0-9-]+$", RegexOptions.Compiled);
    private static readonly Regex VersionRegex = new(@"^v?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$", RegexOptions.Compiled);
    private static readonly Regex DigestRegex = new(@"^sha256:[a-f0-9]{64}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static ManifestValidationResult Validate(ScanToolManifest manifest)
    {
        var errors = new List<string>();

        if (manifest == null)
        {
            return new ManifestValidationResult(false, new[] { "Manifest cannot be null." });
        }

        // 1. ToolKey Validation
        if (string.IsNullOrWhiteSpace(manifest.ToolKey))
        {
            errors.Add("ToolKey cannot be empty.");
        }
        else if (!ToolKeyRegex.IsMatch(manifest.ToolKey))
        {
            errors.Add($"ToolKey '{manifest.ToolKey}' must be lowercase alphanumeric with hyphens only.");
        }

        // 2. Version Validation (Dedicated SemVer/Calendar/Build format)
        if (string.IsNullOrWhiteSpace(manifest.Version))
        {
            errors.Add("Version cannot be empty.");
        }
        else if (!VersionRegex.IsMatch(manifest.Version))
        {
            errors.Add($"Version '{manifest.Version}' does not conform to valid SemVer / Calendar / Build format.");
        }

        // 3. Digest Validation
        if (string.IsNullOrWhiteSpace(manifest.ContainerImageDigest))
        {
            errors.Add("ContainerImageDigest cannot be empty.");
        }
        else if (!DigestRegex.IsMatch(manifest.ContainerImageDigest))
        {
            errors.Add($"ContainerImageDigest '{manifest.ContainerImageDigest}' must be a valid sha256:64-hex string.");
        }
        else
        {
            var rawHex = manifest.ContainerImageDigest.Substring(7).ToLowerInvariant();
            // Disallow known trivial/empty-string or placeholder hashes
            if (rawHex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            {
                errors.Add("ContainerImageDigest cannot be the SHA-256 hash of an empty string.");
            }
            else if (rawHex.Trim('0').Length == 0 || rawHex.Trim('f').Length == 0)
            {
                errors.Add($"ContainerImageDigest '{manifest.ContainerImageDigest}' is a forbidden trivial placeholder hash.");
            }
        }

        // 4. Image Repository & Reference Validation
        if (string.IsNullOrWhiteSpace(manifest.ContainerImageRepository))
        {
            errors.Add("ContainerImageRepository cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(manifest.ContainerImageReference))
        {
            errors.Add("ContainerImageReference cannot be empty.");
        }

        // 5. Supported Profiles Validation
        if (manifest.SupportedProfiles == null || manifest.SupportedProfiles.Count == 0)
        {
            errors.Add("SupportedProfiles must declare at least one SecurityScanProfileType.");
        }

        // 6. Capabilities Validation
        if (manifest.Capabilities == null || manifest.Capabilities.Count == 0)
        {
            errors.Add("Capabilities set must declare at least one capability tag.");
        }

        // 7. Parser Version Validation
        if (string.IsNullOrWhiteSpace(manifest.ParserVersion))
        {
            errors.Add("ParserVersion cannot be empty.");
        }

        return new ManifestValidationResult(errors.Count == 0, errors);
    }
}
