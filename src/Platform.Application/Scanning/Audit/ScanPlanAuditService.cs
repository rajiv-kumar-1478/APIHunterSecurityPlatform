using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Audit.Contracts;
using Platform.Application.Scanning.JavaScript;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Domain.Entities;

namespace Platform.Application.Scanning.Audit;

/// <summary>
/// Authoritative service implementing immutable, cryptographically chained scan plan audit logging,
/// registry snapshots, and forensic provenance lookups.
/// </summary>
public sealed class ScanPlanAuditService : IScanPlanAuditService
{
    public const string GenesisAuditHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private readonly IPlatformDbContext _dbContext;
    private readonly ILogger<ScanPlanAuditService> _logger;

    public ScanPlanAuditService(
        IPlatformDbContext dbContext,
        ILogger<ScanPlanAuditService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<ScanPlanAuditRecord> RecordPlanAuditAsync(
        ResolvedScanPlan plan,
        IScanToolRegistry registry,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(registry);

        // 1. Build Registry Snapshot & Compute Hash
        var allAdapters = registry.GetAllAdapters()
            .OrderBy(a => a.Manifest.ToolKey, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var manifestSnapshots = allAdapters.Select(a => new ToolManifestAuditSnapshot(
            ToolKey: a.Manifest.ToolKey,
            Version: a.Manifest.Version,
            ContainerImageDigest: a.Manifest.ContainerImageDigest,
            Capabilities: a.Manifest.Capabilities.OrderBy(c => c).ToList(),
            ExecutionPhase: a.Manifest.ExecutionPhase.ToString(),
            ParserVersion: a.Manifest.ParserVersion,
            ManifestVersion: a.Manifest.ManifestVersion
        )).ToList();

        var registrySnapshotJson = JsonSerializer.Serialize(manifestSnapshots);
        var registrySnapshotHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(registrySnapshotJson))).ToLowerInvariant();

        // 2. Sanitize Target URL and Selection Reasons (No raw secrets)
        var sanitizedUrl = AiEvidenceProjector.RedactSensitiveMaterial(plan.TargetKind.ToString());
        var sanitizedReasons = new Dictionary<string, string>();
        foreach (var kv in plan.SelectionReasons)
        {
            sanitizedReasons[kv.Key] = AiEvidenceProjector.RedactSensitiveMaterial(kv.Value);
        }

        // 3. Retrieve Previous Audit Hash for Tamper-Evident Chain
        var previousRecord = await _dbContext.ScanPlanAudits
            .Where(a => a.TenantId == plan.TenantId)
            .OrderByDescending(a => a.PlannedAtUtc)
            .FirstOrDefaultAsync(ct);

        var previousAuditHash = previousRecord?.RecordHash ?? GenesisAuditHash;

        // 4. Compute Tamper-Evident RecordHash
        var canonicalAuditString = $"{plan.ScanJobId}:{plan.TenantId}:{plan.PlanHash}:{registrySnapshotHash}:{string.Join(",", plan.ExecutionSequence)}:{plan.PlannerVersion}:{previousAuditHash}";
        var recordHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalAuditString))).ToLowerInvariant();

        var auditRecord = new ScanPlanAuditRecord
        {
            Id = Guid.NewGuid(),
            ScanJobId = plan.ScanJobId,
            TenantId = plan.TenantId,
            TargetUrl = sanitizedUrl,
            TargetKind = plan.TargetKind.ToString(),
            Profile = plan.Profile.ToString(),
            PlanHash = plan.PlanHash,
            PlannerVersion = plan.PlannerVersion,
            RegistrySnapshotHash = registrySnapshotHash,
            ExecutionSequenceJson = JsonSerializer.Serialize(plan.ExecutionSequence),
            SelectionReasonsJson = JsonSerializer.Serialize(sanitizedReasons),
            RuleSetVersionsJson = JsonSerializer.Serialize(plan.RuleSetVersions),
            ToolManifestSnapshotsJson = registrySnapshotJson,
            CapabilitySnapshotJson = JsonSerializer.Serialize(plan.PlannedInvocations.SelectMany(i => i.SatisfiedCapabilities).Distinct().OrderBy(c => c)),
            SelectionPolicySnapshotJson = JsonSerializer.Serialize(plan.SelectionReasons),
            PreviousAuditHash = previousAuditHash,
            RecordHash = recordHash,
            PlannedAtUtc = DateTime.UtcNow
        };

        _dbContext.ScanPlanAudits.Add(auditRecord);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("Recorded scan plan audit for Job '{JobId}' (PlanHash: {PlanHash}, RecordHash: {RecordHash}).",
            plan.ScanJobId, plan.PlanHash, recordHash);

        return auditRecord;
    }

    public async Task<ScanProvenanceResponse?> GetProvenanceAsync(
        Guid scanJobId,
        Guid tenantId,
        CancellationToken ct = default)
    {
        var record = await _dbContext.ScanPlanAudits
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.ScanJobId == scanJobId && a.TenantId == tenantId, ct);

        if (record == null) return null;

        var sequence = JsonSerializer.Deserialize<List<string>>(record.ExecutionSequenceJson) ?? new List<string>();
        var rules = JsonSerializer.Deserialize<Dictionary<string, string>>(record.RuleSetVersionsJson) ?? new Dictionary<string, string>();
        var reasons = JsonSerializer.Deserialize<Dictionary<string, string>>(record.SelectionReasonsJson) ?? new Dictionary<string, string>();
        var manifests = JsonSerializer.Deserialize<List<ToolManifestAuditSnapshot>>(record.ToolManifestSnapshotsJson) ?? new List<ToolManifestAuditSnapshot>();

        return new ScanProvenanceResponse(
            ScanJobId: record.ScanJobId,
            TenantId: record.TenantId,
            TargetUrl: record.TargetUrl,
            TargetKind: record.TargetKind,
            Profile: record.Profile,
            PlanHash: record.PlanHash,
            PlannerVersion: record.PlannerVersion,
            RegistrySnapshotHash: record.RegistrySnapshotHash,
            ExecutionSequence: sequence.AsReadOnly(),
            RuleSetVersions: rules,
            SelectionReasons: reasons,
            ToolManifestSnapshots: manifests.AsReadOnly(),
            PreviousAuditHash: record.PreviousAuditHash,
            RecordHash: record.RecordHash,
            PlannedAtUtc: record.PlannedAtUtc
        );
    }

    public async Task<IReadOnlyList<ScanPlanAuditRecord>> GetAuditHistoryAsync(
        Guid tenantId,
        int limit = 50,
        CancellationToken ct = default)
    {
        var records = await _dbContext.ScanPlanAudits
            .AsNoTracking()
            .Where(a => a.TenantId == tenantId)
            .OrderByDescending(a => a.PlannedAtUtc)
            .Take(Math.Clamp(limit, 1, 100))
            .ToListAsync(ct);

        return records.AsReadOnly();
    }
}
