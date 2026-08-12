using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record TransitionFindingStatusRequest(
    Guid FindingId,
    FindingStatus NewStatus,
    int ExpectedLifecycleVersion,
    string? Reason);

public record SecurityFindingStatusHistoryDto(
    Guid Id,
    Guid FindingId,
    FindingStatus FromStatus,
    FindingStatus ToStatus,
    Guid? ChangedByUserId,
    string Reason,
    string MetadataJson,
    DateTime CreatedAtUtc);

/// <summary>
/// Encapsulates state machine governance, optimistic concurrency control,
/// and append-only status transition auditing for SecurityFinding domain records.
/// </summary>
public class SecurityFindingLifecycleService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;
    private readonly ICurrentUserContext _currentUser;
    private readonly ILogger<SecurityFindingLifecycleService> _logger;

    public SecurityFindingLifecycleService(
        IPlatformDbContext dbContext,
        SecurityFindingService findingService,
        ICurrentUserContext currentUser,
        ILogger<SecurityFindingLifecycleService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _findingService = findingService ?? throw new ArgumentNullException(nameof(findingService));
        _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Executes a governance transition on a finding's status.
    /// Atomically updates finding status, increments concurrency version, appends status history,
    /// logs audit event, and recalculates repository active risk posture.
    /// </summary>
    public async Task<SecurityFinding> TransitionFindingStatusAsync(TransitionFindingStatusRequest req, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(req);

        var actorUserId = _currentUser.UserId;
        string cleanReason = req.Reason?.Trim() ?? string.Empty;

        // 1. Mandatory Reason for Governance Transitions (Remediated, AcceptedRisk, FalsePositive, Resolved)
        if (IsGovernanceStatus(req.NewStatus) && string.IsNullOrWhiteSpace(cleanReason))
        {
            throw new ArgumentException($"A non-empty reason is mandatory when transitioning finding to governance status '{req.NewStatus}'.", nameof(req.Reason));
        }

        // 2. Fetch finding
        var finding = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .FirstOrDefaultAsync(f => f.Id == req.FindingId, ct)
            ?? throw new KeyNotFoundException($"SecurityFinding '{req.FindingId}' was not found.");

        // 3. Early Concurrency Check
        if (req.ExpectedLifecycleVersion != finding.LifecycleVersion)
        {
            _logger.LogWarning("Concurrency conflict for SecurityFinding '{FindingId}': expected version {Expected}, found {Actual}.", req.FindingId, req.ExpectedLifecycleVersion, finding.LifecycleVersion);
            throw new DbUpdateConcurrencyException($"Concurrency conflict for SecurityFinding '{req.FindingId}': expected version {req.ExpectedLifecycleVersion}, but current version is {finding.LifecycleVersion}.");
        }

        // 4. Validate State Machine Transition Matrix
        if (!IsValidTransition(finding.Status, req.NewStatus))
        {
            _logger.LogWarning("Invalid status transition for SecurityFinding '{FindingId}': '{FromStatus}' -> '{ToStatus}'.", req.FindingId, finding.Status, req.NewStatus);
            throw new InvalidOperationException($"Invalid status transition from '{finding.Status}' to '{req.NewStatus}' for SecurityFinding '{req.FindingId}'.");
        }

        FindingStatus fromStatus = finding.Status;

        // 5. Update Finding entity fields & Option A resolution field isolation
        finding.Status = req.NewStatus;
        finding.LifecycleVersion++;
        finding.LastObservedAtUtc = DateTime.UtcNow;

        if (req.NewStatus == FindingStatus.Resolved)
        {
            finding.ResolvedAtUtc = DateTime.UtcNow;
            finding.ResolvedByUserId = actorUserId;
            finding.ResolutionReason = cleanReason;
        }
        else
        {
            finding.ResolvedAtUtc = null;
            finding.ResolvedByUserId = null;
            finding.ResolutionReason = null;
        }

        // 6. Create append-only history record
        var historyRecord = new SecurityFindingStatusHistory
        {
            FindingId = finding.Id,
            FromStatus = fromStatus,
            ToStatus = req.NewStatus,
            ChangedByUserId = actorUserId,
            Reason = cleanReason,
            MetadataJson = JsonSerializer.Serialize(new
            {
                lifecycleVersion = finding.LifecycleVersion,
                previousLifecycleVersion = req.ExpectedLifecycleVersion
            }),
            CreatedAtUtc = DateTime.UtcNow
        };
        _dbContext.SecurityFindingStatusHistories.Add(historyRecord);

        // 7. Create AuditEvent record
        var auditEvent = new AuditEvent
        {
            EventCode = AuditEventCode.FindingStatusChanged,
            UserId = actorUserId,
            ResourceType = "SecurityFinding",
            ResourceId = finding.Id.ToString(),
            Metadata = JsonSerializer.Serialize(new
            {
                finding.RepositoryId,
                fromStatus = fromStatus.ToString(),
                toStatus = req.NewStatus.ToString(),
                lifecycleVersion = finding.LifecycleVersion,
                reason = cleanReason
            }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString(),
            CreatedAtUtc = DateTime.UtcNow
        };
        _dbContext.AuditEvents.Add(auditEvent);

        // 8. Persist atomically — EF Core wraps all pending changes in a single DB transaction
        //    The IsConcurrencyToken() on LifecycleVersion guarantees that if another writer already
        //    modified this row, SaveChangesAsync raises DbUpdateConcurrencyException, leaving
        //    the DB unchanged (finding status, history record, and audit event all uncommitted).
        try
        {
            await _dbContext.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogError(ex, "DbUpdateConcurrencyException while persisting status transition for finding '{FindingId}'. No changes committed.", finding.Id);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist status transition for finding '{FindingId}'.", finding.Id);
            throw;
        }

        // 9. Recalculate repository risk posture
        await _findingService.RecalculateRepositoryRiskAsync(finding.RepositoryId, ct);

        _logger.LogInformation("Successfully transitioned SecurityFinding '{FindingId}' from '{FromStatus}' to '{ToStatus}' (Version {Version}).", finding.Id, fromStatus, req.NewStatus, finding.LifecycleVersion);
        return finding;
    }

    /// <summary>
    /// Gets append-only status history for a finding.
    /// </summary>
    public async Task<List<SecurityFindingStatusHistoryDto>> GetFindingStatusHistoryAsync(Guid findingId, CancellationToken ct = default)
    {
        return await _dbContext.SecurityFindingStatusHistories
            .Where(h => h.FindingId == findingId)
            .OrderBy(h => h.CreatedAtUtc)
            .Select(h => new SecurityFindingStatusHistoryDto(
                h.Id,
                h.FindingId,
                h.FromStatus,
                h.ToStatus,
                h.ChangedByUserId,
                h.Reason,
                h.MetadataJson,
                h.CreatedAtUtc))
            .ToListAsync(ct);
    }

    /// <summary>
    /// Evaluates whether a status transition is allowed by the formal state machine.
    /// </summary>
    public static bool IsValidTransition(FindingStatus from, FindingStatus to)
    {
        if (from == to) return true; // Idempotent no-op allowed

        return from switch
        {
            FindingStatus.Open => to == FindingStatus.Investigating ||
                                 to == FindingStatus.Confirmed ||
                                 to == FindingStatus.FalsePositive ||
                                 to == FindingStatus.AcceptedRisk,

            FindingStatus.Investigating => to == FindingStatus.Confirmed ||
                                          to == FindingStatus.FalsePositive ||
                                          to == FindingStatus.AcceptedRisk,

            FindingStatus.Confirmed => to == FindingStatus.Remediated ||
                                       to == FindingStatus.AcceptedRisk ||
                                       to == FindingStatus.FalsePositive,

            FindingStatus.Remediated => to == FindingStatus.Resolved ||
                                       to == FindingStatus.Open ||
                                       to == FindingStatus.Investigating,

            FindingStatus.AcceptedRisk => to == FindingStatus.Open ||
                                          to == FindingStatus.Investigating ||
                                          to == FindingStatus.FalsePositive,

            FindingStatus.FalsePositive => to == FindingStatus.Open ||
                                           to == FindingStatus.Investigating,

            FindingStatus.Resolved => to == FindingStatus.Open ||
                                      to == FindingStatus.Investigating,

            _ => false
        };
    }

    private static bool IsGovernanceStatus(FindingStatus status)
    {
        return status == FindingStatus.Remediated ||
               status == FindingStatus.AcceptedRisk ||
               status == FindingStatus.FalsePositive ||
               status == FindingStatus.Resolved;
    }
}
