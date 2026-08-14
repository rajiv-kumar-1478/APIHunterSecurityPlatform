using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Verification;
using Platform.Application.Scanning.Verification.Contracts;
using Xunit;

namespace Platform.UnitTests.Scanning.Verification;

public class DeploymentWebhookHandlerTests
{
    private readonly MockApplicationTargetResolver _mockResolver;
    private readonly DeploymentWebhookHandler _handler;
    private const string TestAppId = "app-prod-100";
    private const string TestSecret = "super-secret-key-12345";
    private const string TestTargetUrl = "https://app.example.com";

    public DeploymentWebhookHandlerTests()
    {
        _mockResolver = new MockApplicationTargetResolver();
        _mockResolver.SetupApplication(TestAppId, new DeploymentTargetResolution(Guid.NewGuid(), TestAppId, TestTargetUrl, "Production", true), TestSecret);
        _handler = new DeploymentWebhookHandler(_mockResolver, NullLogger<DeploymentWebhookHandler>.Instance);
    }

    [Fact]
    public async Task HandleWebhook_ValidSignatureAndFreshTimestamp_SuccessfullyEnqueuesScanJob()
    {
        var rawBody = "{\"applicationId\":\"app-prod-100\",\"deploymentId\":\"dep-42\",\"commitSha\":\"a1b2c3d\"}";
        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        var webhookId = Guid.NewGuid().ToString();

        var signature = ComputeHmacSha256(rawBody, TestSecret);

        var headers = new Dictionary<string, string>
        {
            ["X-Webhook-Id"] = webhookId,
            ["X-Webhook-Timestamp"] = timestamp,
            ["X-Hub-Signature-256"] = $"sha256={signature}"
        };

        var response = await _handler.HandleWebhookAsync(rawBody, headers);

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.ScanJobId);
        Assert.True(_mockResolver.ProcessedWebhookIds.Contains(webhookId));
    }

    [Fact]
    public async Task HandleWebhook_ExpiredTimestamp_RejectsWithTimestampOutOfRange()
    {
        var rawBody = "{\"applicationId\":\"app-prod-100\",\"deploymentId\":\"dep-42\"}";
        // 10 minutes ago
        var expiredTimestamp = DateTimeOffset.UtcNow.AddMinutes(-10).ToString("O");
        var webhookId = Guid.NewGuid().ToString();
        var signature = ComputeHmacSha256(rawBody, TestSecret);

        var headers = new Dictionary<string, string>
        {
            ["X-Webhook-Id"] = webhookId,
            ["X-Webhook-Timestamp"] = expiredTimestamp,
            ["X-Hub-Signature-256"] = $"sha256={signature}"
        };

        var response = await _handler.HandleWebhookAsync(rawBody, headers);

        Assert.False(response.IsSuccess);
        Assert.Equal("TIMESTAMP_OUT_OF_RANGE", response.ErrorCode);
    }

    [Fact]
    public async Task HandleWebhook_DuplicateEventId_RejectsToPreventReplay()
    {
        var rawBody = "{\"applicationId\":\"app-prod-100\",\"deploymentId\":\"dep-42\"}";
        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        var webhookId = "existing-webhook-123";
        _mockResolver.ProcessedWebhookIds.Add(webhookId);

        var signature = ComputeHmacSha256(rawBody, TestSecret);

        var headers = new Dictionary<string, string>
        {
            ["X-Webhook-Id"] = webhookId,
            ["X-Webhook-Timestamp"] = timestamp,
            ["X-Hub-Signature-256"] = $"sha256={signature}"
        };

        var response = await _handler.HandleWebhookAsync(rawBody, headers);

        Assert.False(response.IsSuccess);
        Assert.Equal("DUPLICATE_EVENT_ID", response.ErrorCode);
    }

    [Fact]
    public async Task HandleWebhook_InvalidSignature_RejectsWithInvalidSignature()
    {
        var rawBody = "{\"applicationId\":\"app-prod-100\",\"deploymentId\":\"dep-42\"}";
        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        var webhookId = Guid.NewGuid().ToString();

        var headers = new Dictionary<string, string>
        {
            ["X-Webhook-Id"] = webhookId,
            ["X-Webhook-Timestamp"] = timestamp,
            ["X-Hub-Signature-256"] = "sha256=invalidhash000000000000000000000000000000000000000000000000000000"
        };

        var response = await _handler.HandleWebhookAsync(rawBody, headers);

        Assert.False(response.IsSuccess);
        Assert.Equal("INVALID_SIGNATURE", response.ErrorCode);
    }

    [Fact]
    public async Task HandleWebhook_UnknownApplication_RejectsUnauthorized()
    {
        var rawBody = "{\"applicationId\":\"app-unknown-999\",\"deploymentId\":\"dep-1\"}";
        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        var webhookId = Guid.NewGuid().ToString();

        var headers = new Dictionary<string, string>
        {
            ["X-Webhook-Id"] = webhookId,
            ["X-Webhook-Timestamp"] = timestamp,
            ["X-Hub-Signature-256"] = "sha256=1234"
        };

        var response = await _handler.HandleWebhookAsync(rawBody, headers);

        Assert.False(response.IsSuccess);
        Assert.Equal("UNAUTHORIZED_APPLICATION", response.ErrorCode);
    }

    private static string ComputeHmacSha256(string payload, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private sealed class MockApplicationTargetResolver : IApplicationTargetResolver
    {
        private readonly Dictionary<string, DeploymentTargetResolution> _apps = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _secrets = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> ProcessedWebhookIds = new(StringComparer.OrdinalIgnoreCase);

        public void SetupApplication(string appId, DeploymentTargetResolution resolution, string secret)
        {
            _apps[appId] = resolution;
            _secrets[appId] = secret;
        }

        public Task<DeploymentTargetResolution?> ResolveTargetAsync(string applicationId, CancellationToken ct = default)
        {
            _apps.TryGetValue(applicationId, out var res);
            return Task.FromResult(res);
        }

        public Task<string?> GetWebhookSecretAsync(string applicationId, CancellationToken ct = default)
        {
            _secrets.TryGetValue(applicationId, out var secret);
            return Task.FromResult(secret);
        }

        public Task<bool> HasWebhookBeenProcessedAsync(string webhookId, CancellationToken ct = default)
        {
            return Task.FromResult(ProcessedWebhookIds.Contains(webhookId));
        }

        public Task MarkWebhookProcessedAsync(string webhookId, string applicationId, CancellationToken ct = default)
        {
            ProcessedWebhookIds.Add(webhookId);
            return Task.CompletedTask;
        }
    }
}
