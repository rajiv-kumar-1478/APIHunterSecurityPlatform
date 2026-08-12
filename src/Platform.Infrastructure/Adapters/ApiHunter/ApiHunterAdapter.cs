using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Platform.Application.Configuration;
using Platform.Domain.Contracts;
using Platform.Domain.ValueObjects;

namespace Platform.Infrastructure.Adapters.ApiHunter;

public class ApiHunterAdapter : IApiHunterSource
{
    private readonly string _connectionString;
    private readonly ILogger<ApiHunterAdapter> _logger;

    public ApiHunterAdapter(IOptions<ApiHunterSourceOptions> options, ILogger<ApiHunterAdapter> logger)
    {
        _connectionString = options.Value.ConnectionString;
        _logger = logger;
    }

    public async Task<ApiHunterSourceSummaryDto> GetSummaryAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_connectionString))
        {
            return new ApiHunterSourceSummaryDto(0, 0, 0, 0, false);
        }

        try
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync(ct);

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT 
                    (SELECT COUNT(*) FROM ""APIKeys"") as TotalKeys,
                    (SELECT COUNT(*) FROM ""APIKeys"" WHERE ""Status"" = 1) as ValidKeys,
                    (SELECT COUNT(*) FROM ""APIKeys"" WHERE ""Status"" = 7) as ValidNoCreditsKeys,
                    (SELECT COUNT(*) FROM ""RepoReferences"") as TotalRepoReferences;";

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var totalKeys = reader.GetInt64(0);
                var validKeys = reader.GetInt64(1);
                var validNoCredits = reader.GetInt64(2);
                var totalRepos = reader.GetInt64(3);

                return new ApiHunterSourceSummaryDto(totalKeys, validKeys, validNoCredits, totalRepos, true);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to connect or fetch summary from APIHunter source database.");
        }

        return new ApiHunterSourceSummaryDto(0, 0, 0, 0, false);
    }

    public async Task<List<ApiHunterKeySourceDto>> FetchKeysIncrementalAsync(long lastSyncedId, int batchSize = 1000, CancellationToken ct = default)
    {
        var result = new List<ApiHunterKeySourceDto>();
        if (string.IsNullOrWhiteSpace(_connectionString)) return result;

        try
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync(ct);

            // Fetch keys batch
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT ""Id"", ""ApiKey"", ""Status"", ""ApiType"", ""SearchProvider"", ""LastCheckedUTC"", 
                       ""FirstFoundUTC"", ""LastFoundUTC"", ""ValidationResponse"", ""Balance"", ""AccountTier"", 
                       ""AwsAccountId"", ""AwsRiskLevel""
                FROM ""APIKeys""
                WHERE ""Id"" > @lastSyncedId
                ORDER BY ""Id"" ASC
                LIMIT @batchSize;";

            cmd.Parameters.AddWithValue("lastSyncedId", lastSyncedId);
            cmd.Parameters.AddWithValue("batchSize", batchSize);

            var keyIds = new List<long>();
            var keyMap = new Dictionary<long, ApiHunterKeySourceDto>();

            await using (var reader = await cmd.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    var id = reader.GetInt64(0);
                    var apiKey = reader.GetString(1);
                    var status = reader.GetInt32(2);
                    var apiType = reader.GetInt32(3);
                    var searchProvider = reader.GetInt32(4);
                    var lastChecked = reader.IsDBNull(5) ? (DateTime?)null : reader.GetDateTime(5);
                    var firstFound = reader.GetDateTime(6);
                    var lastFound = reader.GetDateTime(7);
                    var validationResp = reader.IsDBNull(8) ? null : reader.GetString(8);
                    var balance = reader.IsDBNull(9) ? null : reader.GetString(9);
                    var accountTier = reader.IsDBNull(10) ? null : reader.GetString(10);
                    var awsAccount = reader.IsDBNull(11) ? null : reader.GetString(11);
                    var awsRisk = reader.IsDBNull(12) ? null : reader.GetString(12);

                    var dto = new ApiHunterKeySourceDto(
                        id, apiKey, status, apiType, searchProvider, lastChecked, firstFound, lastFound,
                        validationResp, balance, accountTier, awsAccount, awsRisk, new List<ApiHunterRepoSourceDto>());

                    keyIds.Add(id);
                    keyMap[id] = dto;
                    result.Add(dto);
                }
            }

            // Fetch repo references for the fetched key IDs batch
            if (keyIds.Count > 0)
            {
                await using var refCmd = conn.CreateCommand();
                refCmd.CommandText = @"
                    SELECT ""Id"", ""APIKeyId"", ""RepoURL"", ""RepoOwner"", ""RepoName"", ""FilePath"", 
                           ""FileURL"", ""LineNumber"", ""CodeContext"", ""FoundUTC""
                    FROM ""RepoReferences""
                    WHERE ""APIKeyId"" = ANY(@keyIds);";

                refCmd.Parameters.AddWithValue("keyIds", keyIds.ToArray());

                await using var refReader = await refCmd.ExecuteReaderAsync(ct);
                while (await refReader.ReadAsync(ct))
                {
                    var refId = refReader.GetInt64(0);
                    var keyId = refReader.GetInt64(1);
                    var repoUrl = refReader.IsDBNull(2) ? null : refReader.GetString(2);
                    var repoOwner = refReader.IsDBNull(3) ? null : refReader.GetString(3);
                    var repoName = refReader.IsDBNull(4) ? null : refReader.GetString(4);
                    var filePath = refReader.IsDBNull(5) ? null : refReader.GetString(5);
                    var fileUrl = refReader.IsDBNull(6) ? null : refReader.GetString(6);
                    var lineNum = refReader.GetInt32(7);
                    var codeCtx = refReader.IsDBNull(8) ? null : refReader.GetString(8);
                    var foundUtc = refReader.GetDateTime(9);

                    var repoDto = new ApiHunterRepoSourceDto(
                        refId, keyId, repoUrl, repoOwner, repoName, filePath, fileUrl, lineNum, codeCtx, foundUtc);

                    if (keyMap.TryGetValue(keyId, out var keyDto))
                    {
                        keyDto.References.Add(repoDto);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute read-only query against APIHunter database.");
        }

        return result;
    }

    public async Task<ComponentHealthResult> HealthCheckAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_connectionString))
        {
            return new ComponentHealthResult("APIHunterSource", false, "Not Configured", "APIHUNTER_DATABASE_URL not set");
        }

        var sw = Stopwatch.StartNew();
        try
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync(ct);

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT 1;";
            await cmd.ExecuteScalarAsync(ct);
            sw.Stop();

            return new ComponentHealthResult("APIHunterSource", true, "Healthy", "Read-only connection active", sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new ComponentHealthResult("APIHunterSource", false, "Unhealthy", ex.Message, sw.Elapsed);
        }
    }
}
