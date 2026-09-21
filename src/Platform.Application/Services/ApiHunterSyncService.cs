using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

public record ApiHunterRecordDto(
    Guid Id,
    long SourceRecordId,
    string MaskedKey,
    string Status,
    string ApiType,
    string SearchProvider,
    DateTime FirstFoundUtc,
    DateTime LastFoundUtc,
    DateTime? LastCheckedUtc,
    string? Balance,
    string? AccountTier,
    string? AwsAccountId,
    string? AwsRiskLevel,
    int RepoCount);

public record ApiHunterSyncResultDto(
    Guid SyncId,
    string Status,
    long LastSyncedKeyId,
    int RecordsImported,
    int RecordsUpdated,
    int RecordsSkipped,
    DateTime StartedAtUtc,
    DateTime? CompletedAtUtc,
    string? ErrorMessage);

public class ApiHunterSyncService(
    IPlatformDbContext db,
    IApiHunterSource source,
    IApiHunterStatusMapper statusMapper,
    IDataProtectionProvider dataProtectionProvider,
    IAuditService auditService,
    IOptions<ApiHunterSourceOptions> options,
    ILogger<ApiHunterSyncService> logger,
    RepositoryAcquisitionService? repositoryAcquisitionService = null)
{
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("ApiHunter.RawKeys.v1");

    public async Task<ApiHunterSyncResultDto> SynchronizeAsync(CancellationToken ct = default)
    {
        ApiHunterSyncState? syncState = null;
        try
        {
            syncState = await db.ApiHunterSyncStates.OrderByDescending(s => s.LastSyncStartedAtUtc).FirstOrDefaultAsync(ct);
            if (syncState is null)
            {
                syncState = new ApiHunterSyncState
                {
                    LastSyncedKeyId = 0,
                    LastSyncStartedAtUtc = DateTime.UtcNow,
                    Status = SyncStatus.InProgress
                };
                db.ApiHunterSyncStates.Add(syncState);
            }
            else
            {
                syncState.LastSyncStartedAtUtc = DateTime.UtcNow;
                syncState.Status = SyncStatus.InProgress;
                syncState.ErrorMessage = null;
            }

            await db.SaveChangesAsync(ct);
            await auditService.RecordAsync(AuditEventCode.ApiHunterSyncStarted, null, null, "127.0.0.1", new { syncId = syncState.Id, lastSyncedKeyId = syncState.LastSyncedKeyId }, ct);

            // Purge any pre-existing invalid records from platform database
            var invalidRecords = await db.ApiHunterRecords
                .Where(r => r.Status == PlatformKeyStatus.Invalid)
                .ToListAsync(ct);
            if (invalidRecords.Count > 0)
            {
                db.ApiHunterRecords.RemoveRange(invalidRecords);
                await db.SaveChangesAsync(ct);
            }

            var batchSize = options.Value.BatchSize > 0 ? options.Value.BatchSize : 1000;
            var fetchedKeys = await source.FetchKeysIncrementalAsync(syncState.LastSyncedKeyId, batchSize, ct);

            int imported = 0;
            int updated = 0;
            int skipped = 0;

            foreach (var keyDto in fetchedKeys)
            {
                var domainStatus = statusMapper.MapStatus(keyDto.Status);
                if (domainStatus == PlatformKeyStatus.Invalid)
                {
                    skipped++;
                    if (keyDto.Id > syncState.LastSyncedKeyId)
                    {
                        syncState.LastSyncedKeyId = keyDto.Id;
                    }
                    continue;
                }

                var existingRecord = await db.ApiHunterRecords
                    .Include(r => r.RepoReferences)
                    .FirstOrDefaultAsync(r => r.SourceRecordId == keyDto.Id, ct);

                var apiTypeStr = statusMapper.MapApiType(keyDto.ApiType);
                var masked = MaskKey(keyDto.ApiKey);
                string encryptedRaw;
                try
                {
                    encryptedRaw = _protector.Protect(keyDto.ApiKey);
                }
                catch (Exception protEx)
                {
                    logger.LogWarning(protEx, "DataProtection protect failed for key ID {KeyId}", keyDto.Id);
                    encryptedRaw = keyDto.ApiKey;
                }

                if (existingRecord is null)
                {
                    var newRecord = new ApiHunterRecord
                    {
                        SourceRecordId = keyDto.Id,
                        MaskedKey = masked,
                        RawKeyEncrypted = encryptedRaw,
                        Status = domainStatus,
                        ApiType = apiTypeStr,
                        SearchProvider = keyDto.SearchProvider == 1 ? "GitHub" : $"Provider_{keyDto.SearchProvider}",
                        FirstFoundUtc = keyDto.FirstFoundUtc,
                        LastFoundUtc = keyDto.LastFoundUtc,
                        LastCheckedUtc = keyDto.LastCheckedUtc,
                        ValidationResponse = keyDto.ValidationResponse,
                        Balance = keyDto.Balance,
                        AccountTier = keyDto.AccountTier,
                        AwsAccountId = keyDto.AwsAccountId,
                        AwsRiskLevel = keyDto.AwsRiskLevel,
                        ImportedAtUtc = DateTime.UtcNow,
                        UpdatedAtUtc = DateTime.UtcNow
                    };

                    foreach (var r in keyDto.References)
                    {
                        newRecord.RepoReferences.Add(new ApiHunterRepoReference
                        {
                            SourceReferenceId = r.Id,
                            RepoUrl = r.RepoUrl ?? string.Empty,
                            RepoOwner = r.RepoOwner ?? string.Empty,
                            RepoName = r.RepoName ?? string.Empty,
                            FilePath = r.FilePath ?? string.Empty,
                            FileUrl = r.FileUrl ?? string.Empty,
                            LineNumber = r.LineNumber,
                            CodeContext = r.CodeContext,
                            FoundUtc = r.FoundUtc
                        });
                    }

                    db.ApiHunterRecords.Add(newRecord);
                    imported++;
                }
                else
                {
                    existingRecord.Status = domainStatus;
                    existingRecord.LastFoundUtc = keyDto.LastFoundUtc;
                    existingRecord.LastCheckedUtc = keyDto.LastCheckedUtc;
                    existingRecord.Balance = keyDto.Balance;
                    existingRecord.AccountTier = keyDto.AccountTier;
                    existingRecord.UpdatedAtUtc = DateTime.UtcNow;

                    foreach (var r in keyDto.References)
                    {
                        if (!existingRecord.RepoReferences.Any(existingRef => existingRef.SourceReferenceId == r.Id))
                        {
                            existingRecord.RepoReferences.Add(new ApiHunterRepoReference
                            {
                                SourceReferenceId = r.Id,
                                RepoUrl = r.RepoUrl ?? string.Empty,
                                RepoOwner = r.RepoOwner ?? string.Empty,
                                RepoName = r.RepoName ?? string.Empty,
                                FilePath = r.FilePath ?? string.Empty,
                                FileUrl = r.FileUrl ?? string.Empty,
                                LineNumber = r.LineNumber,
                                CodeContext = r.CodeContext,
                                FoundUtc = r.FoundUtc
                            });
                        }
                    }
                    updated++;
                }

                if (keyDto.Id > syncState.LastSyncedKeyId)
                {
                    syncState.LastSyncedKeyId = keyDto.Id;
                }
            }

            syncState.RecordsImported += imported;
            syncState.RecordsUpdated += updated;
            syncState.RecordsSkipped += skipped;
            syncState.LastSyncCompletedAtUtc = DateTime.UtcNow;
            syncState.Status = SyncStatus.Completed;

            await db.SaveChangesAsync(ct);
            await auditService.RecordAsync(AuditEventCode.ApiHunterSyncCompleted, null, null, "127.0.0.1", new { syncId = syncState.Id, imported, updated, lastSyncedKeyId = syncState.LastSyncedKeyId }, ct);

            // Automatically feed newly imported repo references into repository acquisition and AI analysis cycle
            if (repositoryAcquisitionService != null)
            {
                try
                {
                    await repositoryAcquisitionService.SeedRepositoriesFromApiHunterAsync(null, ct);
                }
                catch (Exception repoEx)
                {
                    logger.LogWarning(repoEx, "Failed to automatically seed repositories from APIHunter repo references.");
                }
            }

            return new ApiHunterSyncResultDto(
                syncState.Id, syncState.Status.ToString(), syncState.LastSyncedKeyId,
                syncState.RecordsImported, syncState.RecordsUpdated, syncState.RecordsSkipped,
                syncState.LastSyncStartedAtUtc, syncState.LastSyncCompletedAtUtc, null);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "APIHunter synchronization failed.");
            if (syncState != null)
            {
                try
                {
                    syncState.Status = SyncStatus.Failed;
                    syncState.ErrorMessage = ex.Message;
                    await db.SaveChangesAsync(ct);
                    await auditService.RecordAsync(AuditEventCode.ApiHunterSyncFailed, null, null, "127.0.0.1", new { syncId = syncState.Id, error = ex.Message }, ct);
                }
                catch (Exception dbEx)
                {
                    logger.LogWarning(dbEx, "Failed to save failed sync state to database.");
                }
            }

            return new ApiHunterSyncResultDto(
                syncState?.Id ?? Guid.Empty, "Failed", syncState?.LastSyncedKeyId ?? 0,
                syncState?.RecordsImported ?? 0, syncState?.RecordsUpdated ?? 0, syncState?.RecordsSkipped ?? 0,
                syncState?.LastSyncStartedAtUtc ?? DateTime.UtcNow, DateTime.UtcNow, ex.Message);
        }
    }

    public async Task<ApiHunterKeyDetailsDto?> RevealKeyDetailsAsync(Guid recordId, CancellationToken ct = default)
    {
        var record = await db.ApiHunterRecords
            .Include(r => r.RepoReferences)
            .FirstOrDefaultAsync(r => r.Id == recordId, ct);
        if (record is null) return null;

        await auditService.RecordAsync(
            AuditEventCode.CredentialRevealed, 
            null, 
            null, 
            "127.0.0.1", 
            new { recordId, sourceRecordId = record.SourceRecordId }, 
            ct);

        ApiHunterKeyDetailsDto? liveDetails = null;
        if (record.SourceRecordId > 0)
        {
            try
            {
                liveDetails = await source.GetKeyDetailsAsync(record.SourceRecordId, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to fetch live key details from APIHunter source for key ID {KeyId}", record.SourceRecordId);
            }
        }

        if (liveDetails != null && !string.IsNullOrWhiteSpace(liveDetails.ApiKey))
        {
            // Cache plaintext key in local record so it persists
            try
            {
                if (record.RawKeyEncrypted != liveDetails.ApiKey)
                {
                    record.RawKeyEncrypted = liveDetails.ApiKey;
                    record.UpdatedAtUtc = DateTime.UtcNow;
                    await db.SaveChangesAsync(ct);
                }
            }
            catch (Exception dbEx)
            {
                logger.LogWarning(dbEx, "Failed to update cached key in local record {RecordId}", recordId);
            }

            return liveDetails;
        }

        // Fallback: Reconstruct from local record if source DB is unreachable
        string unmaskedKey = record.RawKeyEncrypted;
        if (!string.IsNullOrWhiteSpace(record.RawKeyEncrypted))
        {
            try
            {
                unmaskedKey = _protector.Unprotect(record.RawKeyEncrypted);
            }
            catch
            {
                try
                {
                    var base64Bytes = Convert.FromBase64String(record.RawKeyEncrypted);
                    var decoded = System.Text.Encoding.UTF8.GetString(base64Bytes);
                    if (!string.IsNullOrWhiteSpace(decoded) && !record.RawKeyEncrypted.StartsWith("CfDJ8"))
                    {
                        unmaskedKey = decoded;
                    }
                }
                catch
                {
                    unmaskedKey = record.RawKeyEncrypted;
                }
            }
        }

        var firstFoundUtc = record.FirstFoundUtc.Kind == DateTimeKind.Utc ? record.FirstFoundUtc : DateTime.SpecifyKind(record.FirstFoundUtc, DateTimeKind.Utc);
        var firstFoundIst = firstFoundUtc.AddHours(5).AddMinutes(30).ToString("yyyy-MM-dd HH:mm:ss");

        string? lastCheckedIst = null;
        if (record.LastCheckedUtc.HasValue)
        {
            var lastCheckedUtc = record.LastCheckedUtc.Value.Kind == DateTimeKind.Utc ? record.LastCheckedUtc.Value : DateTime.SpecifyKind(record.LastCheckedUtc.Value, DateTimeKind.Utc);
            lastCheckedIst = lastCheckedUtc.AddHours(5).AddMinutes(30).ToString("yyyy-MM-dd HH:mm:ss");
        }

        ApiHunterAwsMetadataDto? fallbackAws = null;
        if (!string.IsNullOrEmpty(record.AwsAccountId) || !string.IsNullOrEmpty(record.AwsRiskLevel))
        {
            fallbackAws = new ApiHunterAwsMetadataDto(record.AwsAccountId, null, null, null, null, record.AwsRiskLevel, false);
        }

        var sources = record.RepoReferences.Select(r => new ApiHunterSourceReferenceDto(
            !string.IsNullOrWhiteSpace(r.FileUrl) ? r.FileUrl : r.RepoUrl,
            r.FoundUtc
        )).ToList();

        int statusCode = record.Status switch
        {
            PlatformKeyStatus.Valid => 1,
            PlatformKeyStatus.ValidNoCredits => 7,
            PlatformKeyStatus.Invalid => 0,
            PlatformKeyStatus.Unverified => -99,
            PlatformKeyStatus.Error => 6,
            _ => -99
        };

        return new ApiHunterKeyDetailsDto(
            ApiKey: unmaskedKey,
            ApiTypeName: record.ApiType,
            Status: statusCode,
            StatusName: record.Status.ToString(),
            SearchProvider: record.SearchProvider,
            Balance: record.Balance,
            AccountTier: record.AccountTier,
            FirstFoundUTC: record.FirstFoundUtc,
            LastFoundUTC: record.LastFoundUtc,
            LastCheckedUTC: record.LastCheckedUtc,
            ErrorCount: 0,
            FirstFoundIST: firstFoundIst,
            LastCheckedIST: lastCheckedIst,
            TimesDisplayed: 0,
            ValidationResponse: record.ValidationResponse,
            Metadata: null,
            DiscoveredByTelegramId: null,
            AwsMetadata: fallbackAws,
            Sources: sources
        );
    }

    public async Task<string?> RevealKeyAsync(Guid recordId, CancellationToken ct = default)
    {
        var details = await RevealKeyDetailsAsync(recordId, ct);
        return details?.ApiKey;
    }

    private static string MaskKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return "*****";
        if (key.Length <= 8) return $"{key[0]}****{key[^1]}";
        return $"{key[..4]}****{key[^4..]}";
    }
}
