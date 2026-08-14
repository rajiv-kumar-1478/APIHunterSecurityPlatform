using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Audit.Contracts;
using Platform.Application.Scanning.Planning.Contracts;
using Platform.Domain.Entities;

namespace Platform.Application.Scanning.Audit;

/// <summary>
/// Authoritative service for recording and querying immutable, tamper-evident scan plan audit chains
/// and forensic container provenance.
/// </summary>
public interface IScanPlanAuditService
{
    /// <summary>
    /// Records an immutable, cryptographically chained audit record for a resolved scan plan.
    /// </summary>
    Task<ScanPlanAuditRecord> RecordPlanAuditAsync(
        ResolvedScanPlan plan,
        IScanToolRegistry registry,
        CancellationToken ct = default);

    /// <summary>
    /// Retrieves tenant-scoped forensic provenance for a given scan job.
    /// </summary>
    Task<ScanProvenanceResponse?> GetProvenanceAsync(
        Guid scanJobId,
        Guid tenantId,
        CancellationToken ct = default);

    /// <summary>
    /// Retrieves recent audit records for a tenant.
    /// </summary>
    Task<IReadOnlyList<ScanPlanAuditRecord>> GetAuditHistoryAsync(
        Guid tenantId,
        int limit = 50,
        CancellationToken ct = default);
}
