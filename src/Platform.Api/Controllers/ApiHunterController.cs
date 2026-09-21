using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
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
    RepositoryAcquisitionService acquisitionService,
    ICurrentUserContext currentUser,
    IMemoryCache cache,
    ILogger<ApiHunterController> logger) : ControllerBase
{
    private const string SummaryCacheKey = "apihunter:summary:payload";
    private const string FiltersCacheKey = "apihunter:filters:payload";

    public record AnalyzeUrlRequest(string Url);

    [HttpGet("summary")]
    [RequireAuth]
    public async Task<IActionResult> GetSummary(CancellationToken ct)
    {
        try
        {
            if (cache.TryGetValue(SummaryCacheKey, out object? cachedPayload) && cachedPayload != null)
            {
                return Ok(cachedPayload);
            }

            var sourceSummary = await source.GetSummaryAsync(ct);

            // Consolidated single query for local database counts
            var statusCounts = await db.ApiHunterRecords
                .Where(r => r.Status == PlatformKeyStatus.Valid || r.Status == PlatformKeyStatus.ValidNoCredits)
                .GroupBy(r => r.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToListAsync(ct);

            var importedValid = statusCounts.FirstOrDefault(x => x.Status == PlatformKeyStatus.Valid)?.Count ?? 0;
            var importedValidNoCredits = statusCounts.FirstOrDefault(x => x.Status == PlatformKeyStatus.ValidNoCredits)?.Count ?? 0;
            var importedTotal = importedValid + importedValidNoCredits;
            var importedRepos = await db.ApiHunterRepoReferences.CountAsync(ct);

            var lastSync = await db.ApiHunterSyncStates.OrderByDescending(s => s.LastSyncStartedAtUtc).FirstOrDefaultAsync(ct);

            var availableApiTypes = await db.ApiHunterRecords
                .Where(r => (r.Status == PlatformKeyStatus.Valid || r.Status == PlatformKeyStatus.ValidNoCredits) && !string.IsNullOrEmpty(r.ApiType))
                .Select(r => r.ApiType)
                .Distinct()
                .OrderBy(t => t)
                .ToListAsync(ct);

            var payload = new
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
            };

            cache.Set(SummaryCacheKey, payload, TimeSpan.FromSeconds(60));
            return Ok(payload);
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
            if (cache.TryGetValue(FiltersCacheKey, out object? cachedFilters) && cachedFilters != null)
            {
                return Ok(cachedFilters);
            }

            var apiTypes = await db.ApiHunterRecords
                .Where(r => (r.Status == PlatformKeyStatus.Valid || r.Status == PlatformKeyStatus.ValidNoCredits) && !string.IsNullOrEmpty(r.ApiType))
                .Select(r => r.ApiType)
                .Distinct()
                .OrderBy(t => t)
                .ToListAsync(ct);

            var providers = await db.ApiHunterRecords
                .Where(r => (r.Status == PlatformKeyStatus.Valid || r.Status == PlatformKeyStatus.ValidNoCredits) && !string.IsNullOrEmpty(r.SearchProvider))
                .Select(r => r.SearchProvider)
                .Distinct()
                .OrderBy(p => p)
                .ToListAsync(ct);

            var payload = new { apiTypes, providers };
            cache.Set(FiltersCacheKey, payload, TimeSpan.FromMinutes(10));
            return Ok(payload);
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
                .Where(r => r.Status == PlatformKeyStatus.Valid || r.Status == PlatformKeyStatus.ValidNoCredits);

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
            cache.Remove(SummaryCacheKey);
            cache.Remove(FiltersCacheKey);
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

    [HttpPost("analyze-repos")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AnalyzeAllLeakedRepos(CancellationToken ct)
    {
        try
        {
            var count = await acquisitionService.QueueAllPendingRepositoryAnalysesAsync(currentUser.UserId, ct);
            return Ok(new
            {
                success = true,
                queuedCount = count,
                message = count > 0
                    ? $"Successfully dispatched {count} repository acquisition & analysis jobs."
                    : "All discovered repositories are already queued, running, or acquired."
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while dispatching bulk repository analysis");
            return StatusCode(500, new { title = "Failed to dispatch repository analysis", error = ex.Message });
        }
    }

    [HttpPost("records/{id:guid}/analyze-repos")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AnalyzeRecordRepos([FromRoute] Guid id, CancellationToken ct)
    {
        try
        {
            var count = await acquisitionService.QueueRepositoryAnalysisByRecordIdAsync(id, currentUser.UserId, ct);
            return Ok(new
            {
                success = true,
                queuedCount = count,
                message = count > 0
                    ? $"Dispatched {count} repository analysis jobs for record {id}."
                    : "All linked repositories for this credential record are already queued, currently analyzing, or already processed."
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while dispatching repository analysis for record {RecordId}", id);
            return StatusCode(500, new { title = "Failed to dispatch repository analysis", error = ex.Message });
        }
    }

    [HttpPost("analyze-url")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AnalyzeRepoUrl([FromBody] AnalyzeUrlRequest request, CancellationToken ct)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request?.Url))
            {
                return BadRequest(new { title = "Repository URL is required" });
            }

            var repo = await acquisitionService.QueueRepositoryAnalysisByUrlAsync(request.Url, currentUser.UserId, ct);
            return Ok(new
            {
                success = true,
                repositoryId = repo.Id,
                fullName = repo.FullName,
                url = repo.Url,
                status = repo.AcquisitionStatus.ToString(),
                message = $"Queued acquisition & snapshot analysis for repository '{repo.FullName}'."
            });
        }
        catch (Octokit.NotFoundException nfEx)
        {
            logger.LogWarning(nfEx, "Repository not found on GitHub for URL {Url}", request?.Url);
            return NotFound(new { title = "Repository not found", error = $"Repository does not exist or is private on GitHub: {nfEx.Message}" });
        }
        catch (Octokit.RateLimitExceededException rlEx)
        {
            logger.LogWarning(rlEx, "GitHub API rate limit exceeded while querying {Url}", request?.Url);
            return StatusCode(429, new { title = "GitHub rate limit exceeded", error = "GitHub API rate limit exceeded. Please wait or configure GitHub credentials." });
        }
        catch (Octokit.ApiException apiEx)
        {
            logger.LogWarning(apiEx, "GitHub API error for {Url}", request?.Url);
            return StatusCode((int)apiEx.StatusCode, new { title = "GitHub API Error", error = apiEx.Message });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { title = "Invalid repository URL", error = ex.Message });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error occurred while dispatching repository analysis for URL {Url}", request?.Url);
            return StatusCode(500, new { title = "Failed to dispatch repository analysis", error = ex.Message });
        }
    }
}
