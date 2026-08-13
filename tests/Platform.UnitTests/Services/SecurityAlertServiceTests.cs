using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class SecurityAlertServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<INotificationService> _mockNotificationService;
    private readonly SecurityAlertOptions _options;
    private readonly SecurityAlertService _service;

    public SecurityAlertServiceTests()
    {
        var dbOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("AlertServiceDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(dbOptions);

        _mockNotificationService = new Mock<INotificationService>();

        _options = new SecurityAlertOptions
        {
            GlobalEnabled = true,
            CooldownMinutes = 60,
            HighSeverityThreshold = 60,
            CriticalSeverityThreshold = 80,
            RiskJumpThreshold = 25,
            AlertRecipientEmail = "alerts@security.platform"
        };

        _service = new SecurityAlertService(
            _dbContext,
            _mockNotificationService.Object,
            Options.Create(_options),
            new Mock<ILogger<SecurityAlertService>>().Object);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    // ─── T1: Revoked Credential Always Triggers Alert ─────────────────────────

    [Fact]
    public async Task T1_Revoked_Credential_Always_Triggers_Alert()
    {
        var candidate = new CredentialCandidate
        {
            CredentialType = "openai",
            SecretFingerprint = Guid.NewGuid().ToString("N"),
            MaskedValue = "sk-proj-****1234",
            EncryptedRawValue = "encrypted"
        };
        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        var result = await _service.EvaluateAndAlertForStateChangeAsync(candidate.Id, ValidationStatus.Revoked, ValidationStatus.Valid);

        Assert.True(result);
        _mockNotificationService.Verify(n => n.SendAsync(It.Is<Notification>(notif =>
            notif.Subject.Contains("Revoked") && notif.RecipientEmail == _options.AlertRecipientEmail), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── T2: Expired Credential Always Triggers Alert ─────────────────────────

    [Fact]
    public async Task T2_Expired_Credential_Always_Triggers_Alert()
    {
        var candidate = new CredentialCandidate
        {
            CredentialType = "aws_sts",
            SecretFingerprint = Guid.NewGuid().ToString("N"),
            MaskedValue = "AKIA****5678",
            EncryptedRawValue = "encrypted"
        };
        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        var result = await _service.EvaluateAndAlertForStateChangeAsync(candidate.Id, ValidationStatus.Expired, ValidationStatus.Valid);

        Assert.True(result);
        _mockNotificationService.Verify(n => n.SendAsync(It.Is<Notification>(notif =>
            notif.Subject.Contains("Expired")), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── T3: Critical Threshold Crossing Triggers Alert Even If Delta Small ────

    [Fact]
    public async Task T3_Critical_Threshold_Crossing_Triggers_Alert_Even_If_Delta_Small()
    {
        var repo = new Repository { FullName = "octocat/critical-repo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        // 85 -> 95 is delta 10 (< 25 RiskJumpThreshold), but 95 >= 80 (CriticalSeverityThreshold)
        var result = await _service.EvaluateAndAlertForRiskEscalationAsync(repo.Id, 85, 95);

        Assert.True(result);
        _mockNotificationService.Verify(n => n.SendAsync(It.Is<Notification>(notif =>
            notif.Subject.Contains("Risk Escalation") && notif.Body.Contains("95/100")), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── T4: High Threshold Crossing Triggers Alert ───────────────────────────

    [Fact]
    public async Task T4_High_Threshold_Crossing_Triggers_Alert()
    {
        var repo = new Repository { FullName = "octocat/high-repo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        // 50 -> 65 crosses 60 threshold
        var result = await _service.EvaluateAndAlertForRiskEscalationAsync(repo.Id, 50, 65);

        Assert.True(result);
        _mockNotificationService.Verify(n => n.SendAsync(It.Is<Notification>(notif =>
            notif.Body.Contains("65/100")), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── T5: Large Risk Escalation Delta Triggers Alert ──────────────────────

    [Fact]
    public async Task T5_Large_Risk_Escalation_Delta_Triggers_Alert()
    {
        var repo = new Repository { FullName = "octocat/delta-repo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        // 10 -> 40 is delta 30 >= 25 (RiskJumpThreshold)
        var result = await _service.EvaluateAndAlertForRiskEscalationAsync(repo.Id, 10, 40);

        Assert.True(result);
        _mockNotificationService.Verify(n => n.SendAsync(It.Is<Notification>(notif =>
            notif.Body.Contains("40/100")), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── T6: Low Risk Change Below Thresholds Is Suppressed ─────────────────

    [Fact]
    public async Task T6_Low_Risk_Change_Below_Thresholds_Is_Suppressed()
    {
        var repo = new Repository { FullName = "octocat/low-repo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        // 10 -> 20 (delta 10 < 25, new 20 < 60)
        var result = await _service.EvaluateAndAlertForRiskEscalationAsync(repo.Id, 10, 20);

        Assert.False(result);
        _mockNotificationService.Verify(n => n.SendAsync(It.IsAny<Notification>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ─── T7: Atomic Claim Prevents Concurrent Duplicate Alerts ──────────────

    [Fact]
    public async Task T7_Atomic_Claim_Prevents_Concurrent_Duplicate_Alerts()
    {
        var repo = new Repository { FullName = "octocat/concurrent-repo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.Critical,
            Confidence = FindingConfidence.High,
            Title = "Critical Exposure",
            Description = "Concurrent test finding",
            RiskScore = 90
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        // Run two concurrent tasks evaluating the exact same finding
        var task1 = _service.EvaluateAndAlertForFindingAsync(finding, "ConcurrentTest");
        var task2 = _service.EvaluateAndAlertForFindingAsync(finding, "ConcurrentTest");

        var results = await Task.WhenAll(task1, task2);

        // Exactly one call should return true (sent), and one false (suppressed/claimed)
        Assert.Single(results, r => r);
        Assert.Single(results, r => !r);

        _mockNotificationService.Verify(n => n.SendAsync(It.IsAny<Notification>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ─── T8: Cooldown Suppresses Subsequent Alerts Within Window ─────────────

    [Fact]
    public async Task T8_Cooldown_Suppresses_Subsequent_Alerts_Within_Window()
    {
        var repo = new Repository { FullName = "octocat/cooldown-repo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        var finding = new SecurityFinding
        {
            RepositoryId = repo.Id,
            FindingFingerprint = Guid.NewGuid().ToString("N"),
            FindingType = FindingType.ValidatedCredentialExposed,
            Severity = RiskSeverity.High,
            Confidence = FindingConfidence.High,
            Title = "Cooldown Finding",
            Description = "Test finding",
            RiskScore = 75
        };
        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync();

        // First alert succeeds
        var firstResult = await _service.EvaluateAndAlertForFindingAsync(finding, "CooldownTest");
        Assert.True(firstResult);

        // Second alert immediately after is suppressed by cooldown
        var secondResult = await _service.EvaluateAndAlertForFindingAsync(finding, "CooldownTest");
        Assert.False(secondResult);

        // Verify audit event for suppression was emitted
        var audit = await _dbContext.AuditEvents
            .FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.AlertSuppressedByCooldown);
        Assert.NotNull(audit);
    }

    // ─── T9: Secret Masking Guaranteed In Subject And Body ────────────────────

    [Fact]
    public async Task T9_Secret_Masking_Guaranteed_In_Subject_And_Body()
    {
        var rawSecret = "sk-proj-1234567890abcdef1234567890abcdef";
        var maskedSecret = "sk-proj-****abcd";

        var candidate = new CredentialCandidate
        {
            CredentialType = "openai",
            SecretFingerprint = Guid.NewGuid().ToString("N"),
            MaskedValue = maskedSecret,
            EncryptedRawValue = rawSecret // Should NEVER appear in output
        };
        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        Notification capturedNotif = null!;
        _mockNotificationService
            .Setup(n => n.SendAsync(It.IsAny<Notification>(), It.IsAny<CancellationToken>()))
            .Callback<Notification, CancellationToken>((n, _) => capturedNotif = n)
            .Returns(Task.CompletedTask);

        await _service.EvaluateAndAlertForStateChangeAsync(candidate.Id, ValidationStatus.Revoked, ValidationStatus.Valid);

        Assert.NotNull(capturedNotif);
        Assert.DoesNotContain(rawSecret, capturedNotif.Subject);
        Assert.DoesNotContain(rawSecret, capturedNotif.Body);
        Assert.Contains(maskedSecret, capturedNotif.Body);
    }

    // ─── T10: Fail Closed When GlobalEnabled Is False ─────────────────────────

    [Fact]
    public async Task T10_Fail_Closed_When_GlobalEnabled_Is_False()
    {
        var disabledOptions = new SecurityAlertOptions
        {
            GlobalEnabled = false,
            AlertRecipientEmail = "alerts@security.platform"
        };

        var disabledService = new SecurityAlertService(
            _dbContext,
            _mockNotificationService.Object,
            Options.Create(disabledOptions),
            new Mock<ILogger<SecurityAlertService>>().Object);

        var candidate = new CredentialCandidate
        {
            CredentialType = "openai",
            SecretFingerprint = Guid.NewGuid().ToString("N"),
            MaskedValue = "sk-****",
            EncryptedRawValue = "secret"
        };
        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();

        var result = await disabledService.EvaluateAndAlertForStateChangeAsync(candidate.Id, ValidationStatus.Revoked, ValidationStatus.Valid);

        Assert.False(result);
        _mockNotificationService.Verify(n => n.SendAsync(It.IsAny<Notification>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
