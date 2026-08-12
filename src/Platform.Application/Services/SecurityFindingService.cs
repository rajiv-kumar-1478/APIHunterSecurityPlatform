using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Configuration;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record SecurityFindingDto(
    Guid Id,
    Guid RepositoryId,
    Guid? SnapshotId,
    string FindingFingerprint,
    FindingType FindingType,
    RiskSeverity Severity,
    FindingConfidence Confidence,
    FindingStatus Status,
    string Title,
    string Description,
    int RiskScore,
    string RiskFactorBreakdownJson,
    DateTime FirstObservedAtUtc,
    DateTime LastObservedAtUtc,
    DateTime? ResolvedAtUtc,
    Guid? ResolvedByUserId,
    string? ResolutionReason,
    DateTime CreatedAtUtc,
    int EvidenceCount);

public record SecurityFindingEvidenceDto(
    Guid Id,
    Guid FindingId,
    FindingEvidenceType EvidenceType,
    DiscoveryType DiscoverySource,
    string EvidenceFingerprint,
    Guid? SnapshotId,
    Guid? SnapshotFileId,
    Guid? CandidateId,
    Guid? ValidationResultId,
    Guid? IntelligenceNodeId,
    Guid? IntelligenceEdgeId,
    string EvidenceReference,
    string SafeEvidenceJson,
    DateTime CreatedAtUtc);

public record CreateOrUpdateFindingRequest(
    Guid RepositoryId,
    Guid? SnapshotId,
    FindingType FindingType,
    RiskSeverity Severity,
    FindingConfidence Confidence,
    string Title,
    string Description,
    string CoreEntityId);

public record AttachEvidenceRequest(
    FindingEvidenceType EvidenceType,
    DiscoveryType DiscoverySource,
    string SourceEntityId,
    Guid? SnapshotId = null,
    Guid? SnapshotFileId = null,
    Guid? CandidateId = null,
    Guid? ValidationResultId = null,
    Guid? IntelligenceNodeId = null,
    Guid? IntelligenceEdgeId = null,
    string EvidenceReference = "",
    string SafeEvidenceJson = "{}");

public class SecurityFindingService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly RiskEngine _riskEngine;
    private readonly ILogger<SecurityFindingService> _logger;
    private readonly SecurityAlertService? _alertService;

    public SecurityFindingService(
        IPlatformDbContext dbContext,
        RiskEngine riskEngine,
        ILogger<SecurityFindingService> logger,
        SecurityAlertService? alertService = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _riskEngine = riskEngine ?? throw new ArgumentNullException(nameof(riskEngine));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _alertService = alertService;
    }

    public static string ComputeFindingFingerprint(Guid repositoryId, FindingType findingType, string coreEntityId)
    {
        string raw = $"{repositoryId:N}:{findingType}:{coreEntityId.Trim().ToLowerInvariant()}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexStringLower(hash);
    }

    public static string ComputeEvidenceFingerprint(Guid findingId, FindingEvidenceType evidenceType, string sourceEntityId)
    {
        string raw = $"{findingId:N}:{evidenceType}:{sourceEntityId.Trim().ToLowerInvariant()}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexStringLower(hash);
    }

    public async Task<SecurityFinding> UpsertFindingAsync(CreateOrUpdateFindingRequest req, CancellationToken ct = default)
    {
        string fingerprint = ComputeFindingFingerprint(req.RepositoryId, req.FindingType, req.CoreEntityId);

        var existing = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .FirstOrDefaultAsync(f => f.FindingFingerprint == fingerprint, ct);

        if (existing != null)
        {
            existing.LastObservedAtUtc = DateTime.UtcNow;
            existing.Title = req.Title;
            existing.Description = req.Description;
            existing.Confidence = req.Confidence;
            if (req.SnapshotId.HasValue) existing.SnapshotId = req.SnapshotId.Value;

            var riskResult = _riskEngine.CalculateFindingRisk(existing, existing.Evidences);
            existing.RiskScore = riskResult.Score;
            existing.Severity = riskResult.Severity;
            existing.RiskFactorBreakdownJson = riskResult.ToJson();

            await _dbContext.SaveChangesAsync(ct);
            await RecalculateRepositoryRiskAsync(existing.RepositoryId, ct);

            _logger.LogInformation("Updated existing SecurityFinding '{FindingId}' (Fingerprint: {Fingerprint}, RiskScore: {Score}).", existing.Id, fingerprint, existing.RiskScore);
            return existing;
        }

        var finding = new SecurityFinding
        {
            RepositoryId = req.RepositoryId,
            SnapshotId = req.SnapshotId,
            FindingFingerprint = fingerprint,
            FindingType = req.FindingType,
            Severity = req.Severity,
            Confidence = req.Confidence,
            Status = FindingStatus.Open,
            Title = req.Title,
            Description = req.Description,
            RiskScore = 0,
            RiskFactorBreakdownJson = "[]",
            FirstObservedAtUtc = DateTime.UtcNow,
            LastObservedAtUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow
        };

        var initialRisk = _riskEngine.CalculateFindingRisk(finding, Enumerable.Empty<SecurityFindingEvidence>());
        finding.RiskScore = initialRisk.Score;
        finding.Severity = initialRisk.Severity;
        finding.RiskFactorBreakdownJson = initialRisk.ToJson();

        _dbContext.SecurityFindings.Add(finding);
        await _dbContext.SaveChangesAsync(ct);
        await RecalculateRepositoryRiskAsync(finding.RepositoryId, ct);

        if (_alertService != null)
        {
            try
            {
                await _alertService.EvaluateAndAlertForFindingAsync(finding, "NewFindingDetected", ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed evaluating alert for finding '{FindingId}'.", finding.Id);
            }
        }

        _logger.LogInformation("Created new SecurityFinding '{FindingId}' (Fingerprint: {Fingerprint}, RiskScore: {Score}).", finding.Id, fingerprint, finding.RiskScore);
        return finding;
    }

    public async Task<SecurityFindingEvidence> AttachEvidenceAsync(Guid findingId, AttachEvidenceRequest req, CancellationToken ct = default)
    {
        var finding = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .FirstOrDefaultAsync(f => f.Id == findingId, ct)
            ?? throw new KeyNotFoundException($"SecurityFinding '{findingId}' not found.");

        string evidenceFingerprint = ComputeEvidenceFingerprint(findingId, req.EvidenceType, req.SourceEntityId);

        var existing = await _dbContext.SecurityFindingEvidences
            .FirstOrDefaultAsync(e => e.FindingId == findingId && e.EvidenceFingerprint == evidenceFingerprint, ct);

        if (existing != null)
        {
            return existing;
        }

        var evidence = new SecurityFindingEvidence
        {
            FindingId = findingId,
            EvidenceType = req.EvidenceType,
            DiscoverySource = req.DiscoverySource,
            EvidenceFingerprint = evidenceFingerprint,
            SnapshotId = req.SnapshotId,
            SnapshotFileId = req.SnapshotFileId,
            CandidateId = req.CandidateId,
            ValidationResultId = req.ValidationResultId,
            IntelligenceNodeId = req.IntelligenceNodeId,
            IntelligenceEdgeId = req.IntelligenceEdgeId,
            EvidenceReference = req.EvidenceReference,
            SafeEvidenceJson = req.SafeEvidenceJson,
            CreatedAtUtc = DateTime.UtcNow
        };

        _dbContext.SecurityFindingEvidences.Add(evidence);
        if (!finding.Evidences.Any(e => e.EvidenceFingerprint == evidenceFingerprint))
        {
            finding.Evidences.Add(evidence);
        }
        finding.LastObservedAtUtc = DateTime.UtcNow;

        var updatedRisk = _riskEngine.CalculateFindingRisk(finding, finding.Evidences);
        finding.RiskScore = updatedRisk.Score;
        finding.Severity = updatedRisk.Severity;
        finding.RiskFactorBreakdownJson = updatedRisk.ToJson();

        await _dbContext.SaveChangesAsync(ct);
        await RecalculateRepositoryRiskAsync(finding.RepositoryId, ct);

        return evidence;
    }

    public async Task<SecurityFinding> UpdateFindingStatusAsync(Guid findingId, FindingStatus newStatus, Guid? resolvedByUserId = null, string? resolutionReason = null, CancellationToken ct = default)
    {
        var finding = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .FirstOrDefaultAsync(f => f.Id == findingId, ct)
            ?? throw new KeyNotFoundException($"SecurityFinding '{findingId}' not found.");

        finding.Status = newStatus;
        finding.LastObservedAtUtc = DateTime.UtcNow;

        if (newStatus == FindingStatus.Resolved || newStatus == FindingStatus.Remediated || newStatus == FindingStatus.AcceptedRisk || newStatus == FindingStatus.FalsePositive)
        {
            finding.ResolvedAtUtc = DateTime.UtcNow;
            finding.ResolvedByUserId = resolvedByUserId;
            finding.ResolutionReason = resolutionReason;
        }
        else
        {
            finding.ResolvedAtUtc = null;
            finding.ResolvedByUserId = null;
            finding.ResolutionReason = null;
        }

        var updatedRisk = _riskEngine.CalculateFindingRisk(finding, finding.Evidences);
        finding.RiskScore = updatedRisk.Score;
        finding.Severity = updatedRisk.Severity;
        finding.RiskFactorBreakdownJson = updatedRisk.ToJson();

        await _dbContext.SaveChangesAsync(ct);

        // Recalculate repository aggregate score (excluded statuses contribute 0 to active repo risk)
        await RecalculateRepositoryRiskAsync(finding.RepositoryId, ct);

        _logger.LogInformation("Updated Status of SecurityFinding '{FindingId}' to '{NewStatus}'.", findingId, newStatus);
        return finding;
    }

    public async Task RecalculateRepositoryRiskAsync(Guid repositoryId, CancellationToken ct = default)
    {
        var activeFindings = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .Where(f => f.RepositoryId == repositoryId && (f.Status == FindingStatus.Open || f.Status == FindingStatus.Investigating || f.Status == FindingStatus.Confirmed))
            .ToListAsync(ct);

        var activeRiskResults = activeFindings
            .Select(f => _riskEngine.CalculateFindingRisk(f, f.Evidences))
            .ToList();

        var repoRiskResult = _riskEngine.CalculateRepositoryRisk(repositoryId, activeRiskResults);

        var existingRepoRisk = await _dbContext.RepositoryRiskScores
            .FirstOrDefaultAsync(r => r.RepositoryId == repositoryId, ct);

        int oldScore = existingRepoRisk?.Score ?? 0;
        int newScore = repoRiskResult.Score;

        if (existingRepoRisk != null)
        {
            existingRepoRisk.Score = newScore;
            existingRepoRisk.Severity = repoRiskResult.Severity;
            existingRepoRisk.AlgorithmVersion = repoRiskResult.AlgorithmVersion;
            existingRepoRisk.FactorBreakdownJson = repoRiskResult.FactorBreakdownJson;
            existingRepoRisk.CalculatedAtUtc = DateTime.UtcNow;
        }
        else
        {
            var newRepoRisk = new RepositoryRiskScore
            {
                RepositoryId = repositoryId,
                Score = newScore,
                Severity = repoRiskResult.Severity,
                AlgorithmVersion = repoRiskResult.AlgorithmVersion,
                FactorBreakdownJson = repoRiskResult.FactorBreakdownJson,
                CalculatedAtUtc = DateTime.UtcNow
            };
            _dbContext.RepositoryRiskScores.Add(newRepoRisk);
        }

        await _dbContext.SaveChangesAsync(ct);

        if (_alertService != null)
        {
            try
            {
                await _alertService.EvaluateAndAlertForRiskEscalationAsync(repositoryId, oldScore, newScore, ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed evaluating risk escalation alert for repository '{RepositoryId}'.", repositoryId);
            }
        }
    }

    public async Task<(List<SecurityFindingDto> Items, int TotalCount)> GetFindingsAsync(
        Guid? repositoryId = null,
        RiskSeverity? severity = null,
        FindingStatus? status = null,
        FindingType? findingType = null,
        int page = 1,
        int pageSize = 20,
        CancellationToken ct = default)
    {
        var query = _dbContext.SecurityFindings.AsQueryable();

        if (repositoryId.HasValue) query = query.Where(f => f.RepositoryId == repositoryId.Value);
        if (severity.HasValue) query = query.Where(f => f.Severity == severity.Value);
        if (status.HasValue) query = query.Where(f => f.Status == status.Value);
        if (findingType.HasValue) query = query.Where(f => f.FindingType == findingType.Value);

        int totalCount = await query.CountAsync(ct);

        var dtos = await query
            .OrderByDescending(f => f.LastObservedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(f => new SecurityFindingDto(
                f.Id,
                f.RepositoryId,
                f.SnapshotId,
                f.FindingFingerprint,
                f.FindingType,
                f.Severity,
                f.Confidence,
                f.Status,
                f.Title,
                f.Description,
                f.RiskScore,
                f.RiskFactorBreakdownJson,
                f.FirstObservedAtUtc,
                f.LastObservedAtUtc,
                f.ResolvedAtUtc,
                f.ResolvedByUserId,
                f.ResolutionReason,
                f.CreatedAtUtc,
                f.Evidences.Count
            ))
            .ToListAsync(ct);

        return (dtos, totalCount);
    }

    public async Task<SecurityFindingDto> GetFindingByIdAsync(Guid findingId, CancellationToken ct = default)
    {
        var f = await _dbContext.SecurityFindings
            .Include(x => x.Evidences)
            .FirstOrDefaultAsync(x => x.Id == findingId, ct)
            ?? throw new KeyNotFoundException($"SecurityFinding '{findingId}' not found.");

        return new SecurityFindingDto(
            f.Id,
            f.RepositoryId,
            f.SnapshotId,
            f.FindingFingerprint,
            f.FindingType,
            f.Severity,
            f.Confidence,
            f.Status,
            f.Title,
            f.Description,
            f.RiskScore,
            f.RiskFactorBreakdownJson,
            f.FirstObservedAtUtc,
            f.LastObservedAtUtc,
            f.ResolvedAtUtc,
            f.ResolvedByUserId,
            f.ResolutionReason,
            f.CreatedAtUtc,
            f.Evidences.Count
        );
    }

    public async Task<List<SecurityFindingEvidenceDto>> GetFindingEvidencesAsync(Guid findingId, CancellationToken ct = default)
    {
        return await _dbContext.SecurityFindingEvidences
            .Where(ev => ev.FindingId == findingId)
            .OrderBy(ev => ev.CreatedAtUtc)
            .Select(ev => new SecurityFindingEvidenceDto(
                ev.Id,
                ev.FindingId,
                ev.EvidenceType,
                ev.DiscoverySource,
                ev.EvidenceFingerprint,
                ev.SnapshotId,
                ev.SnapshotFileId,
                ev.CandidateId,
                ev.ValidationResultId,
                ev.IntelligenceNodeId,
                ev.IntelligenceEdgeId,
                ev.EvidenceReference,
                ev.SafeEvidenceJson,
                ev.CreatedAtUtc
            ))
            .ToListAsync(ct);
    }
}
