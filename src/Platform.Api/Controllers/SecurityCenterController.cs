using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

public record SecurityPostureDto(
    int TotalRepositoriesMonitored,
    int HighestRepositoryRiskScore,
    string OverallSeverity,
    int OpenFindingsCount,
    int CriticalFindingsCount,
    int HighFindingsCount,
    int ValidatedCredentialsCount,
    DateTime CalculatedAtUtc);

public record AlertingStatusDto(
    bool Enabled,
    int CooldownMinutes,
    int HighSeverityThreshold,
    int CriticalSeverityThreshold,
    int RiskJumpThreshold);

[ApiController]
[Route("api/v1/security-center")]
[Authorize]
public class SecurityCenterController(
    IPlatformDbContext dbContext,
    IOptions<SecurityAlertOptions> alertOptions,
    ICurrentUserContext currentUser,
    PermissionService permissionService) : ControllerBase
{
    private readonly SecurityAlertOptions _alertOptions = alertOptions.Value;

    /// <summary>
    /// Returns aggregated security posture statistics.
    /// STRICT BOUNDARY: Reads persisted RepositoryRiskScore DB rows only — does NOT invoke RiskEngine directly.
    /// </summary>
    [HttpGet("posture")]
    public async Task<IActionResult> GetSecurityPosture(CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue
                && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.view", ct);
            if (!hasPermission) return Forbid();
        }

        var totalRepos = await dbContext.Repositories.CountAsync(ct);

        // Read highest persisted risk score from DB
        var topRiskScore = await dbContext.RepositoryRiskScores
            .OrderByDescending(r => r.Score)
            .FirstOrDefaultAsync(ct);

        int highestScore = topRiskScore?.Score ?? 0;
        RiskSeverity overallSeverity = topRiskScore?.Severity ?? RiskSeverity.Low;

        var openFindings = await dbContext.SecurityFindings
            .Where(f => f.Status == FindingStatus.Open || f.Status == FindingStatus.Investigating || f.Status == FindingStatus.Confirmed)
            .ToListAsync(ct);

        int openCount = openFindings.Count;
        int criticalCount = openFindings.Count(f => f.Severity == RiskSeverity.Critical);
        int highCount = openFindings.Count(f => f.Severity == RiskSeverity.High);

        var validResultsCount = await dbContext.CredentialValidationResults
            .Where(r => r.Status == ValidationStatus.Valid || r.Status == ValidationStatus.ValidInsufficientScope)
            .CountAsync(ct);

        var postureDto = new SecurityPostureDto(
            TotalRepositoriesMonitored: totalRepos,
            HighestRepositoryRiskScore: highestScore,
            OverallSeverity: overallSeverity.ToString(),
            OpenFindingsCount: openCount,
            CriticalFindingsCount: criticalCount,
            HighFindingsCount: highCount,
            ValidatedCredentialsCount: validResultsCount,
            CalculatedAtUtc: topRiskScore?.CalculatedAtUtc ?? DateTime.UtcNow);

        return Ok(postureDto);
    }

    /// <summary>
    /// Returns sanitized read-only alert subsystem status.
    /// STRICT BOUNDARY: Returns non-sensitive status metadata ONLY.
    /// SMTP/Telegram secrets, API keys, and recipient emails are NEVER exposed.
    /// </summary>
    [HttpGet("alerting-status")]
    public async Task<IActionResult> GetAlertingStatus(CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue
                && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "finding.view", ct);
            if (!hasPermission) return Forbid();
        }

        var dto = new AlertingStatusDto(
            Enabled: _alertOptions.GlobalEnabled,
            CooldownMinutes: _alertOptions.CooldownMinutes,
            HighSeverityThreshold: _alertOptions.HighSeverityThreshold,
            CriticalSeverityThreshold: _alertOptions.CriticalSeverityThreshold,
            RiskJumpThreshold: _alertOptions.RiskJumpThreshold);

        return Ok(dto);
    }
}
