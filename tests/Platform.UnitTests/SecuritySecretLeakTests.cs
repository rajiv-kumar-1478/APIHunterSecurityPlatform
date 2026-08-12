using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Domain.Entities;
using Platform.Infrastructure.Adapters.Detection;
using Xunit;

namespace Platform.UnitTests;

public class SecuritySecretLeakTests
{
    private const string STEP3_TEST_SECRET_DO_NOT_LOG = "sk-proj-STEP3_TEST_SECRET_DO_NOT_LOG_9876543210";

    [Fact]
    public async Task Detector_RedactedLineContent_NeverContainsRawSecret()
    {
        var detectorOptions = Options.Create(new DetectionOptions
        {
            SecretPepper = "security_test_pepper",
            FingerprintKeyVersion = 1,
            MaxFileSizeMb = 5,
            RegexTimeoutSeconds = 2,
            MaxMatchesPerFile = 10
        });

        var detector = new RegexSecretDetector(detectorOptions, NullLogger<RegexSecretDetector>.Instance);

        var rules = new List<DetectionRule>
        {
            new()
            {
                Id = "test-secret-rule",
                Version = 1,
                Description = "Test Secret Rule",
                RegexPattern = @"sk-proj-STEP3_TEST_SECRET[A-Za-z0-9_]{10,}",
                CredentialType = "TestSecret",
                Confidence = "High",
                IsEnabled = true
            }
        };

        var fileContent = $"SECRET_KEY = \"{STEP3_TEST_SECRET_DO_NOT_LOG}\";";

        var matches = await detector.ScanFileAsync("test/secret.env", fileContent, rules);

        Assert.Single(matches);
        var match = matches[0];

        // 1. Redacted line must NOT contain raw secret
        Assert.DoesNotContain(STEP3_TEST_SECRET_DO_NOT_LOG, match.RedactedLineContent);

        // 2. Masked value must NOT contain raw secret
        Assert.DoesNotContain(STEP3_TEST_SECRET_DO_NOT_LOG, match.MaskedValue);

        // 3. HMAC Fingerprint must NOT contain raw secret
        var fp = RegexSecretDetector.ComputeSecretFingerprint(match.RawMatchValue, "security_test_pepper");
        Assert.DoesNotContain(STEP3_TEST_SECRET_DO_NOT_LOG, fp);

        // 4. Redacted line must contain placeholder
        Assert.Contains("****REDACTED****", match.RedactedLineContent);
    }
}
