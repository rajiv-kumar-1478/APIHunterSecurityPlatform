using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Domain.ValueObjects;

namespace Platform.Application.Services;

/// <summary>
/// Security Alert Decision Engine (Phase 6 Step 7).
/// Evaluates security finding creation/updates, validation state changes, and risk score escalations,
/// applies database-backed atomic deduplication and cooldown policies, renders secret-safe templates,
/// and dispatches notifications via INotificationService.
///
/// BOUNDARY GUARANTEES:
///   - Does NOT mutate finding lifecycle statuses (FindingStatus remains untouched).
///   - Does NOT modify RiskEngine.cs or calculate risk directly.
///   - Does NOT decrypt or render raw secrets.
///   - Fails closed if GlobalEnabled = false or recipient email is unconfigured.
/// </summary>
public class SecurityAlertService(
    IPlatformDbContext dbContext,
    INotificationService notificationService,
    IOptions<SecurityAlertOptions> options,
    ILogger<SecurityAlertService> logger)
{
    private readonly SecurityAlertOptions _options = options.Value;

    // ─── Fingerprint Helpers ──────────────────────────────────────────────────

    public static string ComputeFindingAlertFingerprint(string findingFingerprint, string alertReason, string recipient)
    {
        string raw = $"finding:{findingFingerprint.Trim().ToLowerInvariant()}:{alertReason.Trim()}:{recipient.Trim().ToLowerInvariant()}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexStringLower(hash);
    }

    public static string ComputeRepositoryAlertFingerprint(Guid repositoryId, string alertReason, string recipient)
    {
        string raw = $"repository:{repositoryId:N}:{alertReason.Trim()}:{recipient.Trim().ToLowerInvariant()}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexStringLower(hash);
    }

    // ─── Entry Point 1: Finding Alert ────────────────────────────────────────

    public async Task<bool> EvaluateAndAlertForFindingAsync(
        SecurityFinding finding,
        string alertReason,
        CancellationToken ct = default)
    {
        if (!IsConfigured(out string recipient)) return false;

        // Eligibility Check
        bool isEligible = alertReason is "RevokedCredential" or "ExpiredCredential"
            || finding.Severity is RiskSeverity.High or RiskSeverity.Critical
            || finding.RiskScore >= _options.HighSeverityThreshold;

        if (!isEligible)
        {
            logger.LogDebug("Finding '{FindingId}' (Severity: {Severity}, RiskScore: {Score}) not eligible for alert.",
                finding.Id, finding.Severity, finding.RiskScore);
            return false;
        }

        string alertFingerprint = ComputeFindingAlertFingerprint(finding.FindingFingerprint, alertReason, recipient);

        // Atomic DB claim & cooldown check
        var claimLog = await AttemptAtomicAlertClaimAsync(
            alertFingerprint, finding.FindingFingerprint, alertReason, recipient,
            finding.Severity, finding.RiskScore, finding.Id, finding.RepositoryId, null, ct);

        if (claimLog == null) return false; // Suppressed by cooldown or claimed by another worker

        // Load repository name for notification template
        var repo = await dbContext.Repositories
            .FirstOrDefaultAsync(r => r.Id == finding.RepositoryId, ct);
        string repoName = repo?.FullName ?? finding.RepositoryId.ToString();

        // Render Secret-Safe Notification
        var notification = BuildFindingNotification(finding, alertReason, repoName, recipient);

        return await DispatchAndFinalizeAlertAsync(claimLog, notification, finding.Id.ToString(), "SecurityFinding", ct);
    }

    // ─── Entry Point 2: Validation State Change Alert ──────────────────────

    public async Task<bool> EvaluateAndAlertForStateChangeAsync(
        Guid candidateId,
        ValidationStatus newStatus,
        ValidationStatus? oldStatus,
        CancellationToken ct = default)
    {
        if (!IsConfigured(out string recipient)) return false;

        // Explicit event check: Revoked or Expired ALWAYS alert
        bool isExplicitAlert = newStatus is ValidationStatus.Revoked or ValidationStatus.Expired;
        if (!isExplicitAlert)
        {
            logger.LogDebug("Candidate '{CandidateId}' new status '{Status}' is not an explicit alert trigger.", candidateId, newStatus);
            return false;
        }

        string alertReason = newStatus == ValidationStatus.Revoked ? "CredentialRevoked" : "CredentialExpired";

        var candidate = await dbContext.CredentialCandidates
            .FirstOrDefaultAsync(c => c.Id == candidateId, ct);
        if (candidate == null) return false;

        var occurrence = await dbContext.CandidateOccurrences
            .Include(o => o.SnapshotFile)
                .ThenInclude(sf => sf.Snapshot)
            .FirstOrDefaultAsync(o => o.CandidateId == candidateId, ct);
        Guid? repoId = occurrence?.SnapshotFile?.Snapshot?.RepositoryId;

        string findingFingerprint = $"candidate:{candidateId:N}";
        string alertFingerprint = ComputeFindingAlertFingerprint(findingFingerprint, alertReason, recipient);

        var claimLog = await AttemptAtomicAlertClaimAsync(
            alertFingerprint, findingFingerprint, alertReason, recipient,
            RiskSeverity.High, 70, null, repoId, candidateId, ct);

        if (claimLog == null) return false;

        var notification = BuildStateChangeNotification(candidate, newStatus, alertReason, recipient);

        return await DispatchAndFinalizeAlertAsync(claimLog, notification, candidateId.ToString(), "CredentialCandidate", ct);
    }

    // ─── Entry Point 3: Repository Risk Escalation Alert ───────────────────

    public async Task<bool> EvaluateAndAlertForRiskEscalationAsync(
        Guid repositoryId,
        int oldScore,
        int newScore,
        CancellationToken ct = default)
    {
        if (!IsConfigured(out string recipient)) return false;

        int scoreDelta = newScore - oldScore;

        // Triggers:
        // 1. New score >= Critical (80)
        // 2. New score >= High (60) AND old score < High (60)
        // 3. Score delta >= RiskJumpThreshold (+25)
        bool isCritical = newScore >= _options.CriticalSeverityThreshold;
        bool isHighCrossing = newScore >= _options.HighSeverityThreshold && oldScore < _options.HighSeverityThreshold;
        bool isLargeDelta = scoreDelta >= _options.RiskJumpThreshold;

        if (!isCritical && !isHighCrossing && !isLargeDelta)
        {
            logger.LogDebug("Repository '{RepositoryId}' risk change ({OldScore} -> {NewScore}, delta: {Delta}) does not trigger alert.",
                repositoryId, oldScore, newScore, scoreDelta);
            return false;
        }

        string alertReason = isCritical ? "CriticalRiskReached" : isHighCrossing ? "HighRiskThresholdCrossed" : "RiskScoreEscalated";
        string alertFingerprint = ComputeRepositoryAlertFingerprint(repositoryId, alertReason, recipient);

        var repo = await dbContext.Repositories.FirstOrDefaultAsync(r => r.Id == repositoryId, ct);
        string repoName = repo?.FullName ?? repositoryId.ToString();

        RiskSeverity severity = isCritical ? RiskSeverity.Critical : RiskSeverity.High;

        var claimLog = await AttemptAtomicAlertClaimAsync(
            alertFingerprint, $"repository:{repositoryId:N}", alertReason, recipient,
            severity, newScore, null, repositoryId, null, ct);

        if (claimLog == null) return false;

        var notification = BuildRiskEscalationNotification(repositoryId, repoName, oldScore, newScore, alertReason, recipient);

        return await DispatchAndFinalizeAlertAsync(claimLog, notification, repositoryId.ToString(), "Repository", ct);
    }

    // ─── Fail-Closed Configuration Verification ─────────────────────────────

    private bool IsConfigured(out string recipient)
    {
        recipient = _options.AlertRecipientEmail;
        if (!_options.GlobalEnabled)
        {
            logger.LogDebug("SecurityAlertService is disabled (GlobalEnabled = false). Failing closed.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(recipient))
        {
            logger.LogWarning("SecurityAlertService has no configured recipient email. Failing closed.");
            return false;
        }

        return true;
    }

    // ─── Atomic Claim Protocol ──────────────────────────────────────────────

    private async Task<SecurityAlertLog?> AttemptAtomicAlertClaimAsync(
        string alertFingerprint,
        string findingFingerprint,
        string alertReason,
        string recipient,
        RiskSeverity severity,
        int riskScore,
        Guid? findingId,
        Guid? repositoryId,
        Guid? candidateId,
        CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var cooldownCutoff = now.AddMinutes(-_options.CooldownMinutes);

        // Check if alert was sent or claimed within cooldown window
        var existingRecentLog = await dbContext.SecurityAlertLogs
            .FirstOrDefaultAsync(l => l.AlertFingerprint == alertFingerprint
                                   && (l.SentAtUtc >= cooldownCutoff
                                       || (l.ClaimedAtUtc != null && l.ClaimedAtUtc >= now.AddMinutes(-5))), ct);

        if (existingRecentLog != null)
        {
            logger.LogInformation("Alert '{AlertFingerprint}' (Reason: {Reason}) suppressed by cooldown (Sent/Claimed at {Time}).",
                alertFingerprint, alertReason, existingRecentLog.SentAtUtc);

            dbContext.AuditEvents.Add(new AuditEvent
            {
                EventCode = AuditEventCode.AlertSuppressedByCooldown,
                ResourceType = "SecurityAlertLog",
                ResourceId = existingRecentLog.Id.ToString(),
                Metadata = JsonSerializer.Serialize(new
                {
                    alertFingerprint,
                    alertReason,
                    findingFingerprint,
                    sentAt = existingRecentLog.SentAtUtc
                }),
                CorrelationId = Guid.NewGuid().ToString()
            });

            await dbContext.SaveChangesAsync(ct);
            return null;
        }

        // Create atomic claim log
        var claimLog = new SecurityAlertLog
        {
            FindingId = findingId,
            RepositoryId = repositoryId,
            CandidateId = candidateId,
            FindingFingerprint = findingFingerprint,
            AlertReason = alertReason,
            AlertFingerprint = alertFingerprint,
            Severity = severity,
            RiskScore = riskScore,
            Recipient = recipient,
            ClaimToken = Guid.NewGuid(),
            ClaimedAtUtc = now,
            SentAtUtc = now
        };

        dbContext.SecurityAlertLogs.Add(claimLog);

        try
        {
            await dbContext.SaveChangesAsync(ct);
            return claimLog;
        }
        catch (DbUpdateException ex)
        {
            logger.LogWarning(ex, "Atomic alert claim failed for fingerprint '{AlertFingerprint}'. Another worker claimed it concurrently.", alertFingerprint);
            return null;
        }
    }

    // ─── Dispatch & Finalize ─────────────────────────────────────────────────

    private async Task<bool> DispatchAndFinalizeAlertAsync(
        SecurityAlertLog claimLog,
        Notification notification,
        string resourceId,
        string resourceType,
        CancellationToken ct)
    {
        try
        {
            await notificationService.SendAsync(notification, ct);

            // Clear claim token on successful send
            claimLog.ClaimToken = null;
            claimLog.ClaimedAtUtc = null;
            claimLog.SentAtUtc = DateTime.UtcNow;

            dbContext.AuditEvents.Add(new AuditEvent
            {
                EventCode = AuditEventCode.NotificationSent,
                ResourceType = resourceType,
                ResourceId = resourceId,
                Metadata = JsonSerializer.Serialize(new
                {
                    alertFingerprint = claimLog.AlertFingerprint,
                    alertReason = claimLog.AlertReason,
                    recipient = claimLog.Recipient
                }),
                CorrelationId = Guid.NewGuid().ToString()
            });

            await dbContext.SaveChangesAsync(ct);

            logger.LogInformation("Dispatched security alert for {ResourceType} '{ResourceId}' (Reason: {Reason}) to {Recipient}.",
                resourceType, resourceId, claimLog.AlertReason, claimLog.Recipient);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed dispatching notification for {ResourceType} '{ResourceId}'.", resourceType, resourceId);

            dbContext.AuditEvents.Add(new AuditEvent
            {
                EventCode = AuditEventCode.NotificationFailed,
                ResourceType = resourceType,
                ResourceId = resourceId,
                Metadata = JsonSerializer.Serialize(new
                {
                    alertFingerprint = claimLog.AlertFingerprint,
                    error = ex.Message
                }),
                CorrelationId = Guid.NewGuid().ToString()
            });

            await dbContext.SaveChangesAsync(ct);
            return false;
        }
    }

    // ─── Notification Builders (Secret-Safe Formatting) ──────────────────────

    private static Notification BuildFindingNotification(
        SecurityFinding finding,
        string alertReason,
        string repositoryName,
        string recipient)
    {
        string subject = $"[APIHunter Alert] {finding.Severity} Severity Finding: {finding.Title}";

        string bodyHtml = $"""
            <h2>🚨 Security Finding Alert</h2>
            <p><strong>Reason:</strong> {alertReason}</p>
            <p><strong>Repository:</strong> {repositoryName}</p>
            <p><strong>Severity:</strong> <span style="color:red;">{finding.Severity}</span></p>
            <p><strong>Risk Score:</strong> {finding.RiskScore}/100</p>
            <p><strong>Title:</strong> {finding.Title}</p>
            <p><strong>Description:</strong> {finding.Description}</p>
            <p><em>Observed at: {finding.LastObservedAtUtc:yyyy-MM-dd HH:mm:ss} UTC</em></p>
            """;

        return new Notification(
            Subject: subject,
            Body: bodyHtml,
            RecipientEmail: recipient,
            IsHtml: true,
            Metadata: new Dictionary<string, string>
            {
                ["FindingId"] = finding.Id.ToString(),
                ["FindingFingerprint"] = finding.FindingFingerprint,
                ["AlertReason"] = alertReason
            });
    }

    private static Notification BuildStateChangeNotification(
        CredentialCandidate candidate,
        ValidationStatus newStatus,
        string alertReason,
        string recipient)
    {
        // STRICT MASKING: Use candidate.MaskedValue ONLY. Never raw secret!
        string maskedSecret = string.IsNullOrWhiteSpace(candidate.MaskedValue) ? "sk-****" : candidate.MaskedValue;
        string subject = $"[APIHunter Alert] Credential {newStatus}: {candidate.CredentialType}";

        string bodyHtml = $"""
            <h2>⚡ Credential State Change Alert</h2>
            <p><strong>Event:</strong> {alertReason}</p>
            <p><strong>Credential Type:</strong> {candidate.CredentialType}</p>
            <p><strong>Masked Value:</strong> <code>{maskedSecret}</code></p>
            <p><strong>New Status:</strong> <strong>{newStatus}</strong></p>
            <p><em>Detected at: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</em></p>
            """;

        return new Notification(
            Subject: subject,
            Body: bodyHtml,
            RecipientEmail: recipient,
            IsHtml: true,
            Metadata: new Dictionary<string, string>
            {
                ["CandidateId"] = candidate.Id.ToString(),
                ["Status"] = newStatus.ToString(),
                ["AlertReason"] = alertReason
            });
    }

    private static Notification BuildRiskEscalationNotification(
        Guid repositoryId,
        string repositoryName,
        int oldScore,
        int newScore,
        string alertReason,
        string recipient)
    {
        string subject = $"[APIHunter Alert] Repository Risk Escalation: {repositoryName} ({oldScore} ➔ {newScore})";

        string bodyHtml = $"""
            <h2>📈 Repository Risk Escalation Alert</h2>
            <p><strong>Reason:</strong> {alertReason}</p>
            <p><strong>Repository:</strong> {repositoryName}</p>
            <p><strong>Previous Risk Score:</strong> {oldScore}/100</p>
            <p><strong>New Risk Score:</strong> <span style="color:red; font-size:18px;"><strong>{newScore}/100</strong></span></p>
            <p><em>Calculated at: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</em></p>
            """;

        return new Notification(
            Subject: subject,
            Body: bodyHtml,
            RecipientEmail: recipient,
            IsHtml: true,
            Metadata: new Dictionary<string, string>
            {
                ["RepositoryId"] = repositoryId.ToString(),
                ["OldScore"] = oldScore.ToString(),
                ["NewScore"] = newScore.ToString(),
                ["AlertReason"] = alertReason
            });
    }
}
