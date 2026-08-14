using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Authoritative application service managing continuous security scan campaign lifecycles,
/// schedule evaluations, tenant ownership chains, and execution dispatches.
/// </summary>
public interface IScanCampaignService
{
    Task<ScanCampaignDto> CreateCampaignAsync(
        Guid tenantId,
        Guid requestedByUserId,
        CreateCampaignRequest request,
        CancellationToken ct = default);

    Task<ScanCampaignDto?> GetCampaignByIdAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default);

    Task<IReadOnlyList<ScanCampaignDto>> ListCampaignsAsync(
        Guid tenantId,
        Guid? repositoryId = null,
        CampaignStatus? status = null,
        int page = 1,
        int pageSize = 50,
        CancellationToken ct = default);

    Task<ScanCampaignDto> UpdateCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        UpdateCampaignRequest request,
        CancellationToken ct = default);

    Task<ScanCampaignDto> PauseCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        string? reason = null,
        CancellationToken ct = default);

    Task<ScanCampaignDto> ResumeCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default);

    Task<ScanCampaignDto> ArchiveCampaignAsync(
        Guid tenantId,
        Guid campaignId,
        CancellationToken ct = default);

    Task<CampaignRunNowResult> TriggerRunNowAsync(
        Guid tenantId,
        Guid requestedByUserId,
        Guid campaignId,
        CancellationToken ct = default);

    Task<IReadOnlyList<CampaignExecutionAuditLogDto>> GetAuditLogsAsync(
        Guid tenantId,
        Guid campaignId,
        int page = 1,
        int pageSize = 50,
        CancellationToken ct = default);
}
