using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Common;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/apihunter")]
public class ApiHunterController(
    IPlatformDbContext db,
    IApiHunterSource source,
    ApiHunterSyncService syncService,
    ILogger<ApiHunterController> logger) : ControllerBase
{
    [HttpGet("summary")]
    [RequireAuth]
    public async Task<IActionResult> GetSummary(CancellationToken ct)
    {
        try
        {
            var sourceSummary = await source.GetSummaryAsync(ct);

            var importedTotal = await db.ApiHunterRecords.CountAsync(r => r.Status != PlatformKeyStatus.Invalid, ct);
            var importedValid = await db.ApiHunterRecords.CountAsync(r => r.Status == PlatformKeyStatus.Valid, ct);
            var importedValidNoCredits = await db.ApiHunterRecords.CountAsync(r => r.Status == PlatformKeyStatus.ValidNoCredits, ct);
            var importedRepos = await db.ApiHunterRepoReferences.CountAsync(ct);

            var lastSync = await db.ApiHunterSyncStates.OrderByDescending(s => s.LastSyncStartedAtUtc).FirstOrDefaultAsync(ct);

            return Ok(new
            {
                source = sourceSummary,
                imported = new
                {
                    total = importedTotal,
                    valid = importedValid,
                    validNoCredits = importedValidNoCredits,
                    repoReferences = importedRepos
                },
                lastSync = lastSync is null ? null : new
                {
                    lastSync.Id,
                    lastSync.LastSyncedKeyId,
                    status = lastSync.Status.ToString(),
                    lastSync.RecordsImported,
                    lastSync.RecordsUpdated,
                    lastSync.LastSyncStartedAtUtc,
                    lastSync.LastSyncCompletedAtUtc,
                    lastSync.ErrorMessage
                }
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while processing GET api/v1/apihunter/summary");
            return StatusCode(500, new { title = "Failed to retrieve APIHunter summary", error = ex.Message });
        }
    }

    [HttpGet("records")]
    [RequireAuth]
    public async Task<IActionResult> GetRecords(
        [FromQuery] string? status,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken ct = default)
    {
        try
        {
            var query = db.ApiHunterRecords.AsNoTracking()
                .Where(r => r.Status != PlatformKeyStatus.Invalid);

            if (!string.IsNullOrWhiteSpace(status) && !status.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                if (Enum.TryParse<PlatformKeyStatus>(status, true, out var parsedStatus))
                {
                    query = query.Where(r => r.Status == parsedStatus);
                }
            }

            var total = await query.CountAsync(ct);
            var items = await query
                .OrderByDescending(r => r.ImportedAtUtc)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(r => new ApiHunterRecordDto(
                    r.Id,
                    r.SourceRecordId,
                    r.MaskedKey,
                    r.Status.ToString(),
                    r.ApiType,
                    r.SearchProvider,
                    r.FirstFoundUtc,
                    r.LastFoundUtc,
                    r.LastCheckedUtc,
                    r.Balance,
                    r.AccountTier,
                    r.AwsAccountId,
                    r.AwsRiskLevel,
                    r.RepoReferences.Count))
                .ToListAsync(ct);

            return Ok(new PagedResult<ApiHunterRecordDto>(items, total, page, pageSize));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while processing GET api/v1/apihunter/records");
            return StatusCode(500, new { title = "Failed to retrieve APIHunter records", error = ex.Message });
        }
    }

    [HttpPost("sync")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> TriggerSync(CancellationToken ct)
    {
        var result = await syncService.SynchronizeAsync(ct);
        return Ok(result);
    }

    [HttpPost("records/{id:guid}/reveal")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevealKey([FromRoute] Guid id, CancellationToken ct)
    {
        var rawKey = await syncService.RevealKeyAsync(id, ct);
        if (rawKey is null) return NotFound(new { title = "Credential record not found" });

        return Ok(new { recordId = id, rawKey });
    }
}
