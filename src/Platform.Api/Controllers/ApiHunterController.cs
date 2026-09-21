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

            var availableApiTypes = await db.ApiHunterRecords
                .Where(r => !string.IsNullOrEmpty(r.ApiType))
                .Select(r => r.ApiType)
                .Distinct()
                .OrderBy(t => t)
                .ToListAsync(ct);

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
                availableApiTypes,
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

    [HttpGet("filters")]
    [RequireAuth]
    public async Task<IActionResult> GetFilters(CancellationToken ct = default)
    {
        try
        {
            var apiTypes = await db.ApiHunterRecords
                .Where(r => !string.IsNullOrEmpty(r.ApiType))
                .Select(r => r.ApiType)
                .Distinct()
                .OrderBy(t => t)
                .ToListAsync(ct);

            var providers = await db.ApiHunterRecords
                .Where(r => !string.IsNullOrEmpty(r.SearchProvider))
                .Select(r => r.SearchProvider)
                .Distinct()
                .OrderBy(p => p)
                .ToListAsync(ct);

            return Ok(new { apiTypes, providers });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while retrieving filters");
            return StatusCode(500, new { title = "Failed to retrieve filters", error = ex.Message });
        }
    }

    [HttpGet("records")]
    [RequireAuth]
    public async Task<IActionResult> GetRecords(
        [FromQuery] string? status,
        [FromQuery] string? apiType,
        [FromQuery] string? searchProvider,
        [FromQuery] bool? hasRepos,
        [FromQuery] string? search,
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

            if (!string.IsNullOrWhiteSpace(apiType) && !apiType.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                query = query.Where(r => r.ApiType.ToLower() == apiType.ToLower());
            }

            if (!string.IsNullOrWhiteSpace(searchProvider) && !searchProvider.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                query = query.Where(r => r.SearchProvider.ToLower() == searchProvider.ToLower());
            }

            if (hasRepos.HasValue)
            {
                query = hasRepos.Value 
                    ? query.Where(r => r.RepoReferences.Any())
                    : query.Where(r => !r.RepoReferences.Any());
            }

            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = search.Trim().ToLower();
                query = query.Where(r => 
                    r.MaskedKey.ToLower().Contains(term) ||
                    r.ApiType.ToLower().Contains(term) ||
                    r.SearchProvider.ToLower().Contains(term) ||
                    (r.Balance != null && r.Balance.ToLower().Contains(term)) ||
                    (r.AccountTier != null && r.AccountTier.ToLower().Contains(term)) ||
                    r.SourceRecordId.ToString().Contains(term));
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
        try
        {
            var result = await syncService.SynchronizeAsync(ct);
            return Ok(result);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while processing POST api/v1/apihunter/sync");
            return StatusCode(500, new { title = "APIHunter synchronization failed", error = ex.Message });
        }
    }

    [HttpPost("records/{id:guid}/reveal")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevealKey([FromRoute] Guid id, CancellationToken ct)
    {
        try
        {
            var details = await syncService.RevealKeyDetailsAsync(id, ct);
            if (details is null) return NotFound(new { title = "Credential record not found" });

            return Ok(new
            {
                recordId = id,
                rawKey = details.ApiKey,
                details
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while revealing raw key for record {RecordId}", id);
            return StatusCode(500, new { title = "Failed to reveal credential record", error = ex.Message });
        }
    }
}
