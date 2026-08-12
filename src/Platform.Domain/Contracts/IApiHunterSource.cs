using Platform.Domain.ValueObjects;

namespace Platform.Domain.Contracts;

public record ApiHunterKeySourceDto(
    long Id,
    string ApiKey,
    int Status,
    int ApiType,
    int SearchProvider,
    DateTime? LastCheckedUtc,
    DateTime FirstFoundUtc,
    DateTime LastFoundUtc,
    string? ValidationResponse,
    string? Balance,
    string? AccountTier,
    string? AwsAccountId,
    string? AwsRiskLevel,
    List<ApiHunterRepoSourceDto> References);

public record ApiHunterRepoSourceDto(
    long Id,
    long ApiKeyId,
    string? RepoUrl,
    string? RepoOwner,
    string? RepoName,
    string? FilePath,
    string? FileUrl,
    int LineNumber,
    string? CodeContext,
    DateTime FoundUtc);

public record ApiHunterSourceSummaryDto(
    long TotalKeys,
    long ValidKeys,
    long ValidNoCreditsKeys,
    long TotalRepoReferences,
    bool IsConnected);

public interface IApiHunterSource
{
    Task<ApiHunterSourceSummaryDto> GetSummaryAsync(CancellationToken ct = default);
    Task<List<ApiHunterKeySourceDto>> FetchKeysIncrementalAsync(long lastSyncedId, int batchSize = 1000, CancellationToken ct = default);
    Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default);
}
