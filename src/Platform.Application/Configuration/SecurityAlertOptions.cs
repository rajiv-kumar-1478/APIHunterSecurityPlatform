using Platform.Domain.Enums;

namespace Platform.Application.Configuration;

/// <summary>
/// Options for Phase 6 Step 7 — Security Alerting & High-Fidelity Notifications.
/// Bind from appsettings.json section "SecurityAlerts".
/// </summary>
public class SecurityAlertOptions
{
    public const string SectionName = "SecurityAlerts";

    /// <summary>
    /// Master switch — defaults to FALSE (fail-closed).
    /// System will NOT dispatch alerts unless explicitly enabled in configuration.
    /// </summary>
    public bool GlobalEnabled { get; set; } = false;

    /// <summary>
    /// Minimum time between alerts for the exact same AlertFingerprint (minutes). Default: 60.
    /// </summary>
    public int CooldownMinutes { get; set; } = 60;

    /// <summary>
    /// Minimum risk score for High severity threshold crossing (default: 60).
    /// </summary>
    public int HighSeverityThreshold { get; set; } = 60;

    /// <summary>
    /// Minimum risk score for Critical severity threshold crossing (default: 80).
    /// </summary>
    public int CriticalSeverityThreshold { get; set; } = 80;

    /// <summary>
    /// Risk jump delta threshold for triggering risk escalation alert (default: +25).
    /// </summary>
    public int RiskJumpThreshold { get; set; } = 25;

    /// <summary>
    /// Default recipient email address for system security alerts.
    /// Default: empty (must be explicitly configured).
    /// </summary>
    public string AlertRecipientEmail { get; set; } = string.Empty;
}
