using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record CandidateDto(
    Guid Id,
    string MaskedValue,
    string CredentialType,
    CandidateStatus Status,
    DateTime FirstDetectedAtUtc,
    DateTime LastDetectedAtUtc,
    int TotalOccurrences,
    Guid? ResolvedByUserId,
    DateTime? ResolvedAtUtc,
    string? ResolutionNote,
    ValidationStatus? LatestValidationStatus = null,
    ValidationConfidence? LatestValidationConfidence = null,
    DateTime? LatestValidatedAtUtc = null,
    string? LatestValidationClassification = null);

public record CandidateOccurrenceDto(
    Guid Id,
    Guid CandidateId,
    Guid SnapshotFileId,
    Guid RepositoryId,
    string RepositoryFullName,
    string FilePath,
    string DetectionRuleId,
    int RuleVersion,
    int LineNumber,
    int MatchStartIndex,
    int MatchLength,
    string? LineContentRedacted,
    string Confidence,
    DateTime DetectedAtUtc);

public class CandidateService(
    IPlatformDbContext dbContext,
    IDataProtectionProvider dataProtectionProvider,
    IAuditService auditService,
    ICurrentUserContext currentUser,
    PermissionService permissionService)
{
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("Platform.SecretCandidate.RawValue");
    private readonly IDataProtector _contextProtector = dataProtectionProvider.CreateProtector("Platform.CandidateOccurrence.RawContext");

    public async Task<(List<CandidateDto> Items, int TotalCount)> GetCandidatesAsync(
        int page = 1,
        int pageSize = 20,
        CandidateStatus? status = null,
        string? credentialType = null,
        CancellationToken ct = default)
    {
        var isPlatformAdmin = currentUser.IsPlatformAdmin;

        // Candidate view permission check
        if (!isPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.view", ct);
            if (!hasPermission)
            {
                throw new UnauthorizedAccessException("Permission 'candidate.view' is required to view candidates.");
            }
        }

        var query = dbContext.CredentialCandidates.AsQueryable();

        if (status.HasValue)
        {
            query = query.Where(c => c.Status == status.Value);
        }

        if (!string.IsNullOrWhiteSpace(credentialType))
        {
            query = query.Where(c => c.CredentialType == credentialType);
        }

        var totalCount = await query.CountAsync(ct);

        var rawItems = await query
            .OrderByDescending(c => c.LastDetectedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(c => new
            {
                Candidate = c,
                LatestValidation = dbContext.CredentialValidationResults
                    .Where(r => r.CandidateId == c.Id)
                    .OrderByDescending(r => r.ValidatedAtUtc)
                    .FirstOrDefault()
            })
            .ToListAsync(ct);

        var items = rawItems.Select(x => new CandidateDto(
            x.Candidate.Id,
            x.Candidate.MaskedValue,
            x.Candidate.CredentialType,
            x.Candidate.Status,
            x.Candidate.FirstDetectedAtUtc,
            x.Candidate.LastDetectedAtUtc,
            x.Candidate.TotalOccurrences,
            x.Candidate.ResolvedByUserId,
            x.Candidate.ResolvedAtUtc,
            x.Candidate.ResolutionNote,
            x.LatestValidation?.Status,
            x.LatestValidation?.Confidence,
            x.LatestValidation?.ValidatedAtUtc,
            x.LatestValidation?.ResponseClassification
        )).ToList();

        return (items, totalCount);
    }


    public async Task<List<CandidateOccurrenceDto>> GetOccurrencesForCandidateAsync(Guid candidateId, CancellationToken ct = default)
    {
        var isPlatformAdmin = currentUser.IsPlatformAdmin;

        if (!isPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.view", ct);
            if (!hasPermission)
            {
                throw new UnauthorizedAccessException("Permission 'candidate.view' is required to view candidate occurrences.");
            }
        }

        return await dbContext.CandidateOccurrences
            .Where(co => co.CandidateId == candidateId)
            .Include(co => co.Repository)
            .Include(co => co.SnapshotFile)
            .OrderByDescending(co => co.DetectedAtUtc)
            .Select(co => new CandidateOccurrenceDto(
                co.Id,
                co.CandidateId,
                co.SnapshotFileId,
                co.RepositoryId,
                co.Repository.FullName,
                co.SnapshotFile.FilePath,
                co.DetectionRuleId,
                co.RuleVersion,
                co.LineNumber,
                co.MatchStartIndex,
                co.MatchLength,
                co.LineContentRedacted,
                co.Confidence,
                co.DetectedAtUtc))
            .ToListAsync(ct);
    }

    public async Task<string> RevealRawCredentialAsync(Guid candidateId, CancellationToken ct = default)
    {
        var isPlatformAdmin = currentUser.IsPlatformAdmin;

        // Security Boundary: candidate.reveal permission check
        if (!isPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.reveal", ct);
            if (!hasPermission)
            {
                throw new UnauthorizedAccessException("Permission 'candidate.reveal' is required to reveal raw candidate values.");
            }
        }

        var candidate = await dbContext.CredentialCandidates.FirstOrDefaultAsync(c => c.Id == candidateId, ct)
            ?? throw new KeyNotFoundException($"CredentialCandidate with ID {candidateId} not found.");

        var decryptedRaw = _protector.Unprotect(candidate.EncryptedRawValue);

        // Record AuditEvent (Raw key is EXCLUDED from audit metadata for security)
        await auditService.RecordAsync(
            AuditEventCode.SecretCandidateRevealed,
            currentUser.UserId,
            currentUser.SessionId != null ? Guid.Parse(currentUser.SessionId) : null,
            currentUser.IpAddress,
            new
            {
                CandidateId = candidate.Id,
                Fingerprint = candidate.SecretFingerprint,
                CredentialType = candidate.CredentialType
            },
            ct);

        return decryptedRaw;
    }

    public async Task UpdateCandidateStatusAsync(Guid candidateId, CandidateStatus newStatus, string? note = null, CancellationToken ct = default)
    {
        var isPlatformAdmin = currentUser.IsPlatformAdmin;

        if (!isPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "candidate.manage", ct);
            if (!hasPermission)
            {
                throw new UnauthorizedAccessException("Permission 'candidate.manage' is required to update candidate status.");
            }
        }

        var candidate = await dbContext.CredentialCandidates.FirstOrDefaultAsync(c => c.Id == candidateId, ct)
            ?? throw new KeyNotFoundException($"CredentialCandidate with ID {candidateId} not found.");

        var oldStatus = candidate.Status;
        candidate.Status = newStatus;

        if (newStatus == CandidateStatus.Resolved)
        {
            candidate.ResolvedByUserId = currentUser.UserId;
            candidate.ResolvedAtUtc = DateTime.UtcNow;
            candidate.ResolutionNote = note;
        }

        await dbContext.SaveChangesAsync(ct);

        await auditService.RecordAsync(
            AuditEventCode.SecretCandidateStatusChanged,
            currentUser.UserId,
            currentUser.SessionId != null ? Guid.Parse(currentUser.SessionId) : null,
            currentUser.IpAddress,
            new
            {
                CandidateId = candidate.Id,
                OldStatus = oldStatus.ToString(),
                NewStatus = newStatus.ToString(),
                Note = note
            },
            ct);
    }

    public async Task<int> PurgeExpiredRawContextsAsync(int olderThanDays = 30, CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow.AddDays(-olderThanDays);
        var occurrences = await dbContext.CandidateOccurrences
            .Where(co => co.LineContentRawEncrypted != null && co.DetectedAtUtc < cutoff)
            .ToListAsync(ct);

        foreach (var occ in occurrences)
        {
            occ.LineContentRawEncrypted = null;
        }

        await dbContext.SaveChangesAsync(ct);

        await auditService.RecordAsync(
            AuditEventCode.RawContextsPurged,
            currentUser.UserId,
            currentUser.SessionId != null ? Guid.Parse(currentUser.SessionId) : null,
            currentUser.IpAddress,
            new { PurgedCount = occurrences.Count, OlderThanDays = olderThanDays },
            ct);

        return occurrences.Count;
    }
}


