using System.Text.Json.Serialization;
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

public record ApiHunterSourceReferenceDto(
    [property: JsonPropertyName("Source")] string Source,
    [property: JsonPropertyName("FoundUTC")] DateTime FoundUTC);

public record ApiHunterAwsMetadataDto(
    [property: JsonPropertyName("AwsAccountId")] string? AwsAccountId,
    [property: JsonPropertyName("AwsUserArn")] string? AwsUserArn,
    [property: JsonPropertyName("AwsUserId")] string? AwsUserId,
    [property: JsonPropertyName("AwsCredentialType")] string? AwsCredentialType,
    [property: JsonPropertyName("AwsAttachedPolicies")] string? AwsAttachedPolicies,
    [property: JsonPropertyName("AwsRiskLevel")] string? AwsRiskLevel,
    [property: JsonPropertyName("AwsIsRootAccount")] bool AwsIsRootAccount);

public record ApiHunterKeyDetailsDto(
    [property: JsonPropertyName("ApiKey")] string ApiKey,
    [property: JsonPropertyName("ApiTypeName")] string ApiTypeName,
    [property: JsonPropertyName("Status")] int Status,
    [property: JsonPropertyName("StatusName")] string StatusName,
    [property: JsonPropertyName("SearchProvider")] string SearchProvider,
    [property: JsonPropertyName("Balance")] string? Balance,
    [property: JsonPropertyName("AccountTier")] string? AccountTier,
    [property: JsonPropertyName("FirstFoundUTC")] DateTime FirstFoundUTC,
    [property: JsonPropertyName("LastFoundUTC")] DateTime LastFoundUTC,
    [property: JsonPropertyName("LastCheckedUTC")] DateTime? LastCheckedUTC,
    [property: JsonPropertyName("ErrorCount")] int ErrorCount,
    [property: JsonPropertyName("FirstFoundIST")] string FirstFoundIST,
    [property: JsonPropertyName("LastCheckedIST")] string? LastCheckedIST,
    [property: JsonPropertyName("TimesDisplayed")] int TimesDisplayed,
    [property: JsonPropertyName("ValidationResponse")] string? ValidationResponse,
    [property: JsonPropertyName("Metadata")] string? Metadata,
    [property: JsonPropertyName("DiscoveredByTelegramId")] long? DiscoveredByTelegramId,
    [property: JsonPropertyName("AwsMetadata")] ApiHunterAwsMetadataDto? AwsMetadata,
    [property: JsonPropertyName("Sources")] List<ApiHunterSourceReferenceDto> Sources);

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
    Task<ApiHunterKeyDetailsDto?> GetKeyDetailsAsync(long keyId, CancellationToken ct = default);
    Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default);
}
