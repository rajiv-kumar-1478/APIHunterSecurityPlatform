using Platform.Infrastructure.Operations;
using Xunit;

namespace Platform.UnitTests.Operations;

public class OperationalPromptSanitizerTests
{
    private readonly OperationalPromptSanitizer _sanitizer = new();

    [Fact]
    public void Sanitize_RedactsBearerToken()
    {
        var raw = "Error calling endpoint with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID";
        var sanitized = _sanitizer.Sanitize(raw);

        Assert.DoesNotContain("eyJhbGci", sanitized);
        Assert.Contains("Authorization: [REDACTED]", sanitized);
    }

    [Fact]
    public void Sanitize_RedactsAwsAccessKey()
    {
        var raw = "Failed to upload to S3 using AKIAIOSFODNN7EXAMPLE credentials";
        var sanitized = _sanitizer.Sanitize(raw);

        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", sanitized);
        Assert.Contains("AKIA[REDACTED]", sanitized);
    }

    [Fact]
    public void Sanitize_RedactsGitHubToken()
    {
        var raw = "Git clone failed with token ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
        var sanitized = _sanitizer.Sanitize(raw);

        Assert.DoesNotContain("ghp_1234567890abcdefghijklmnopqrstuvwxyz12", sanitized);
        Assert.Contains("ghp_[REDACTED]", sanitized);
    }

    [Fact]
    public void Sanitize_RedactsOpenAiApiKey()
    {
        var raw = "OpenAI request failed using api_key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz";
        var sanitized = _sanitizer.Sanitize(raw);

        Assert.DoesNotContain("sk-proj-1234567890abcdefghijklmnopqrstuvwxyz", sanitized);
        Assert.Contains("sk-[REDACTED]", sanitized);
    }

    [Fact]
    public void Sanitize_RedactsDbPasswordInConnectionString()
    {
        var raw = "Npgsql.NpgsqlException: Host=localhost;Database=sec;Username=postgres;Password=SuperSecretPassword123;";
        var sanitized = _sanitizer.Sanitize(raw);

        Assert.DoesNotContain("SuperSecretPassword123", sanitized);
        Assert.Contains("Password=[REDACTED]", sanitized);
    }

    [Fact]
    public void Sanitize_PreservesBenignStackTraces()
    {
        var raw = "System.TimeoutException: The operation has timed out.\n   at Platform.Worker.ExecuteAsync() in Worker.cs:line 42";
        var sanitized = _sanitizer.Sanitize(raw);

        Assert.Contains("System.TimeoutException", sanitized);
        Assert.Contains("Worker.cs:line 42", sanitized);
    }
}
