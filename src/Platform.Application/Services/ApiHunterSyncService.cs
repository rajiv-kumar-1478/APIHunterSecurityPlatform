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
    ILogger<ApiHunterSyncService> logger)
{
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("ApiHunter.RawKeys.v1");

    public async Task<ApiHunterSyncResultDto> SynchronizeAsync(CancellationToken ct = default)
    {
        var syncState = await db.ApiHunterSyncStates.OrderByDescending(s => s.LastSyncStartedAtUtc).FirstOrDefaultAsync(ct);
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

        try
        {
            var batchSize = options.Value.BatchSize > 0 ? options.Value.BatchSize : 1000;
            var fetchedKeys = await source.FetchKeysIncrementalAsync(syncState.LastSyncedKeyId, batchSize, ct);

            int imported = 0;
            int updated = 0;
            int skipped = 0;

            foreach (var keyDto in fetchedKeys)
            {
                var existingRecord = await db.ApiHunterRecords
                    .Include(r => r.RepoReferences)
                    .FirstOrDefaultAsync(r => r.SourceRecordId == keyDto.Id, ct);

                var domainStatus = statusMapper.MapStatus(keyDto.Status);
                var apiTypeStr = statusMapper.MapApiType(keyDto.ApiType);
                var masked = MaskKey(keyDto.ApiKey);
                var encryptedRaw = _protector.Protect(keyDto.ApiKey);

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

            return new ApiHunterSyncResultDto(
                syncState.Id, syncState.Status.ToString(), syncState.LastSyncedKeyId,
                syncState.RecordsImported, syncState.RecordsUpdated, syncState.RecordsSkipped,
                syncState.LastSyncStartedAtUtc, syncState.LastSyncCompletedAtUtc, null);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "APIHunter synchronization failed.");
            syncState.Status = SyncStatus.Failed;
            syncState.ErrorMessage = ex.Message;
            await db.SaveChangesAsync(ct);
            await auditService.RecordAsync(AuditEventCode.ApiHunterSyncFailed, null, null, "127.0.0.1", new { syncId = syncState.Id, error = ex.Message }, ct);

            return new ApiHunterSyncResultDto(
                syncState.Id, "Failed", syncState.LastSyncedKeyId,
                syncState.RecordsImported, syncState.RecordsUpdated, syncState.RecordsSkipped,
                syncState.LastSyncStartedAtUtc, DateTime.UtcNow, ex.Message);
        }
    }

    public async Task<string?> RevealKeyAsync(Guid recordId, CancellationToken ct = default)
    {
        var record = await db.ApiHunterRecords.FindAsync(new object[] { recordId }, ct);
        if (record is null || string.IsNullOrWhiteSpace(record.RawKeyEncrypted)) return null;

        await auditService.RecordAsync(AuditEventCode.CredentialRevealed, null, null, "127.0.0.1", new { recordId, sourceRecordId = record.SourceRecordId }, ct);
        return _protector.Unprotect(record.RawKeyEncrypted);
    }

    private static string MaskKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return "*****";
        if (key.Length <= 8) return $"{key[0]}****{key[^1]}";
        return $"{key[..4]}****{key[^4..]}";
    }
}
