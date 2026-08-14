using System.Collections.Generic;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Services;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class FindingFingerprintServiceTests
{
    private readonly FindingFingerprintService _service = new();

    [Fact]
    public void ComputeCanonicalFingerprint_SameInput_ReturnsIdenticalHash()
    {
        var hash1 = _service.ComputeCanonicalFingerprint(
            "https://api.example.com/v1/users",
            "sql-injection",
            "POST",
            "username",
            "/v1/users",
            "cwe-89"
        );

        var hash2 = _service.ComputeCanonicalFingerprint(
            "https://api.example.com/v1/users",
            "sql-injection",
            "POST",
            "username",
            "/v1/users",
            "cwe-89"
        );

        Assert.Equal(64, hash1.Length);
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeCanonicalFingerprint_UrlNormalization_StripsDefaultPortAndTrailingSlash()
    {
        var hashWithPort = _service.ComputeCanonicalFingerprint(
            "https://api.example.com:443/",
            "sql-injection"
        );

        var hashClean = _service.ComputeCanonicalFingerprint(
            "https://api.example.com",
            "sql-injection"
        );

        Assert.Equal(hashWithPort, hashClean);
    }

    [Fact]
    public void ComputeCanonicalFingerprint_UrlQueryParameters_SortedAlphabetically()
    {
        var hash1 = _service.ComputeCanonicalFingerprint(
            "https://api.example.com/search?b=2&a=1",
            "xss"
        );

        var hash2 = _service.ComputeCanonicalFingerprint(
            "https://api.example.com/search?a=1&b=2",
            "xss"
        );

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeCanonicalFingerprint_CaseInsensitivityForMethodAndLocation()
    {
        var hashLower = _service.ComputeCanonicalFingerprint(
            "https://api.example.com/api",
            "CWE-89",
            "post",
            "TOKEN",
            "/API"
        );

        var hashUpper = _service.ComputeCanonicalFingerprint(
            "https://api.example.com/api",
            "cwe-89",
            "POST",
            "token",
            "/api"
        );

        Assert.Equal(hashLower, hashUpper);
    }

    [Fact]
    public void ComputeCanonicalFingerprint_NullAndEmptyFields_ProduceDeterministicHash()
    {
        var hash = _service.ComputeCanonicalFingerprint(
            "https://api.example.com",
            "exposed-secret",
            null,
            null,
            null,
            null
        );

        Assert.NotNull(hash);
        Assert.Equal(64, hash.Length);
        Assert.Matches("^[a-f0-9]{64}$", hash);
    }

    [Fact]
    public void ComputeCanonicalFingerprint_CandidateOverload_MatchesDirectCall()
    {
        var candidate = new FindingCandidate(
            ToolKey: "nuclei",
            ToolVersion: "3.2.0",
            FindingType: FindingType.ValidatedCredentialExposed,
            Title: "API Key Leak",
            Description: "Exposed API Key in response",
            RawSeverity: "high",
            TargetUrl: "https://api.example.com/config",
            HttpMethod: "GET",
            ParameterName: "api_key",
            VulnerableLocation: "/config",
            RuleOrTemplateId: "generic-api-key"
        );

        var hashCandidate = _service.ComputeCanonicalFingerprint(candidate);
        var hashDirect = _service.ComputeCanonicalFingerprint(
            "https://api.example.com/config",
            FindingType.ValidatedCredentialExposed.ToString(),
            "GET",
            "api_key",
            "/config",
            "generic-api-key"
        );

        Assert.Equal(hashDirect, hashCandidate);
    }
}
