using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Entities;
using Platform.Infrastructure.Adapters.Detection;
using Xunit;

namespace Platform.UnitTests;

public class RegexSecretDetectorTests
{
    [Fact]
    public void ComputeSecretFingerprint_SameSecretAndKeyVersion_ReturnsSameFingerprint()
    {
        var secret = "sk-proj-1234567890abcdefghijklmn";
        var pepper = "test_pepper_key_2026";

        var fp1 = RegexSecretDetector.ComputeSecretFingerprint(secret, pepper, 1);
        var fp2 = RegexSecretDetector.ComputeSecretFingerprint(secret, pepper, 1);

        Assert.Equal(fp1, fp2);
        Assert.NotEmpty(fp1);
    }

    [Fact]
    public void ComputeSecretFingerprint_DifferentSecrets_ReturnsDifferentFingerprints()
    {
        var secret1 = "sk-proj-1234567890abcdefghijklmn";
        var secret2 = "sk-proj-9999999999abcdefghijklmn";
        var pepper = "test_pepper_key_2026";

        var fp1 = RegexSecretDetector.ComputeSecretFingerprint(secret1, pepper, 1);
        var fp2 = RegexSecretDetector.ComputeSecretFingerprint(secret2, pepper, 1);

        Assert.NotEqual(fp1, fp2);
    }

    [Fact]
    public void ComputeSecretFingerprint_DifferentKeyVersions_ReturnsDifferentFingerprints()
    {
        var secret = "sk-proj-1234567890abcdefghijklmn";
        var pepper = "test_pepper_key_2026";

        var fp1 = RegexSecretDetector.ComputeSecretFingerprint(secret, pepper, 1);
        var fp2 = RegexSecretDetector.ComputeSecretFingerprint(secret, pepper, 2);

        Assert.NotEqual(fp1, fp2);
    }

    [Fact]
    public void MaskSecret_FormatsCorrectly()
    {
        var longKey = "sk-proj-1234567890abcdef";
        var maskedLong = RegexSecretDetector.MaskSecret(longKey);

        Assert.Equal("sk-p****cdef", maskedLong);

        var shortKey = "sk-12345";
        var maskedShort = RegexSecretDetector.MaskSecret(shortKey);

        Assert.Equal("s****5", maskedShort);
    }

    [Fact]
    public void RedactLine_ReplacesSecretWithoutExposingRawValue()
    {
        var rawLine = "OPENAI_API_KEY=\"sk-proj-secret123456\" # config";
        var secret = "sk-proj-secret123456";

        var redacted = RegexSecretDetector.RedactLine(rawLine, secret);

        Assert.Equal("OPENAI_API_KEY=\"****REDACTED****\" # config", redacted);
        Assert.DoesNotContain(secret, redacted);
    }

    [Fact]
    public async Task ScanFileAsync_DetectsMatchingSecrets()
    {
        var detectorOptions = Options.Create(new DetectionOptions
        {
            SecretPepper = "test_pepper",
            FingerprintKeyVersion = 1,
            MaxFileSizeMb = 5,
            RegexTimeoutSeconds = 2,
            MaxMatchesPerFile = 100
        });

        var detector = new RegexSecretDetector(detectorOptions, NullLogger<RegexSecretDetector>.Instance);

        var rules = new List<DetectionRule>
        {
            new()
            {
                Id = "openai-api-key",
                Version = 1,
                Description = "OpenAI API Key",
                RegexPattern = @"sk-[A-Za-z0-9\-]{20,}",
                CredentialType = "OpenAI",
                Confidence = "High",
                IsEnabled = true
            }
        };

        var fileContent = "const apiKey = 'sk-proj-abcdef1234567890123456';\nconsole.log('test');";

        var matches = await detector.ScanFileAsync("src/config.js", fileContent, rules);

        Assert.Single(matches);
        Assert.Equal("openai-api-key", matches[0].RuleId);
        Assert.Equal(1, matches[0].RuleVersion);
        Assert.Equal("OpenAI", matches[0].CredentialType);
        Assert.Equal("sk-proj-abcdef1234567890123456", matches[0].RawMatchValue);
        Assert.Equal("sk-p****3456", matches[0].MaskedValue);
        Assert.DoesNotContain("sk-proj-abcdef1234567890123456", matches[0].RedactedLineContent);
        Assert.Contains("****REDACTED****", matches[0].RedactedLineContent);
    }
}
