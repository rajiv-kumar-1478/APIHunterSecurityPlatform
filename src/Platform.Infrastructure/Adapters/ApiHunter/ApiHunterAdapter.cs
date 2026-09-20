using System.Diagnostics;
using Microsoft.Extensions.Configuration;
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

    public ApiHunterAdapter(
        IOptions<ApiHunterSourceOptions> options,
        IConfiguration configuration,
        ILogger<ApiHunterAdapter> logger)
    {
        var rawConnStr = !string.IsNullOrWhiteSpace(options.Value.ConnectionString)
            ? options.Value.ConnectionString
            : configuration["APIHUNTER_DATABASE_URL"]
              ?? configuration["ApiHunterSource:ConnectionString"]
              ?? configuration["ApiHunterSource__ConnectionString"]
              ?? configuration["Database:ConnectionString"]
              ?? configuration["ConnectionStrings:Default"]
              ?? configuration["DATABASE_URL"];

        _connectionString = Platform.Infrastructure.Persistence.PostgresConnectionStringNormalizer.Normalize(rawConnStr);
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

            var (keysTable, refsTable) = await ResolveTableNamesAsync(conn, ct);

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $@"
                SELECT 
                    (SELECT COUNT(*) FROM {keysTable}) as TotalKeys,
                    (SELECT COUNT(*) FROM {keysTable} WHERE ""Status"" = 1) as ValidKeys,
                    (SELECT COUNT(*) FROM {keysTable} WHERE ""Status"" = 7) as ValidNoCreditsKeys,
                    (SELECT COUNT(*) FROM {refsTable}) as TotalRepoReferences;";

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
            _logger.LogError(ex, "Failed to connect or fetch summary from APIHunter source database. Exception: {Message}", ex.Message);
        }

        return new ApiHunterSourceSummaryDto(0, 0, 0, 0, false);
    }

    public async Task<List<ApiHunterKeySourceDto>> FetchKeysIncrementalAsync(long lastSyncedId, int batchSize = 2500, CancellationToken ct = default)
    {
        var result = new List<ApiHunterKeySourceDto>();
        if (string.IsNullOrWhiteSpace(_connectionString)) return result;

        try
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync(ct);

            var (keysTable, refsTable) = await ResolveTableNamesAsync(conn, ct);

            // Fetch keys batch prioritizing Valid (1) and ValidNoCredits (7) keys first
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $@"
                SELECT ""Id"", ""ApiKey"", ""Status"", ""ApiType"", ""SearchProvider"", ""LastCheckedUTC"", 
                       ""FirstFoundUTC"", ""LastFoundUTC"", ""ValidationResponse"", ""Balance"", ""AccountTier"", 
                       ""AwsAccountId"", ""AwsRiskLevel""
                FROM {keysTable}
                WHERE ""Id"" > @lastSyncedId
                ORDER BY CASE 
                    WHEN ""Status"" = 1 THEN 1 
                    WHEN ""Status"" = 7 THEN 2 
                    WHEN ""Status"" = 6 THEN 3 
                    WHEN ""Status"" = 0 THEN 4 
                    ELSE 5 
                END, ""Id"" ASC
                LIMIT @batchSize;";

            cmd.Parameters.AddWithValue("lastSyncedId", lastSyncedId);
            cmd.Parameters.AddWithValue("batchSize", batchSize);

            var keyIds = new List<long>();
            var keyMap = new Dictionary<long, ApiHunterKeySourceDto>();

            await using (var reader = await cmd.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    try
                    {
                        var id = GetSafeLong(reader, 0);
                        var apiKey = reader.IsDBNull(1) ? null : reader.GetValue(1)?.ToString();
                        if (string.IsNullOrWhiteSpace(apiKey)) continue;

                        var status = GetSafeInt(reader, 2, -99);
                        var apiType = GetSafeInt(reader, 3, -99);
                        var searchProvider = GetSafeInt(reader, 4, 0);
                        var lastChecked = reader.IsDBNull(5) ? (DateTime?)null : GetSafeDateTime(reader, 5);
                        var firstFound = GetSafeDateTime(reader, 6);
                        var lastFound = GetSafeDateTime(reader, 7);
                        var validationResp = reader.IsDBNull(8) ? null : reader.GetValue(8)?.ToString();
                        var balance = reader.IsDBNull(9) ? null : reader.GetValue(9)?.ToString();
                        var accountTier = reader.IsDBNull(10) ? null : reader.GetValue(10)?.ToString();
                        var awsAccount = reader.IsDBNull(11) ? null : reader.GetValue(11)?.ToString();
                        var awsRisk = reader.IsDBNull(12) ? null : reader.GetValue(12)?.ToString();

                        var dto = new ApiHunterKeySourceDto(
                            id, apiKey, status, apiType, searchProvider, lastChecked, firstFound, lastFound,
                            validationResp, balance, accountTier, awsAccount, awsRisk, new List<ApiHunterRepoSourceDto>());

                        keyIds.Add(id);
                        keyMap[id] = dto;
                        result.Add(dto);
                    }
                    catch (Exception rowEx)
                    {
                        _logger.LogWarning(rowEx, "Failed to parse individual APIKey record row.");
                    }
                }
            }

            // Fetch repo references for the fetched key IDs batch
            if (keyIds.Count > 0)
            {
                await using var refCmd = conn.CreateCommand();
                refCmd.CommandText = $@"
                    SELECT ""Id"", ""APIKeyId"", ""RepoURL"", ""RepoOwner"", ""RepoName"", ""FilePath"", 
                           ""FileURL"", ""LineNumber"", ""CodeContext"", ""FoundUTC""
                    FROM {refsTable}
                    WHERE ""APIKeyId"" = ANY(@keyIds);";

                refCmd.Parameters.AddWithValue("keyIds", keyIds.ToArray());

                await using var refReader = await refCmd.ExecuteReaderAsync(ct);
                while (await refReader.ReadAsync(ct))
                {
                    try
                    {
                        var refId = GetSafeLong(refReader, 0);
                        var keyId = GetSafeLong(refReader, 1);
                        var repoUrl = refReader.IsDBNull(2) ? null : refReader.GetValue(2)?.ToString();
                        var repoOwner = refReader.IsDBNull(3) ? null : refReader.GetValue(3)?.ToString();
                        var repoName = refReader.IsDBNull(4) ? null : refReader.GetValue(4)?.ToString();
                        var filePath = refReader.IsDBNull(5) ? null : refReader.GetValue(5)?.ToString();
                        var fileUrl = refReader.IsDBNull(6) ? null : refReader.GetValue(6)?.ToString();
                        var lineNum = GetSafeInt(refReader, 7, 0);
                        var codeCtx = refReader.IsDBNull(8) ? null : refReader.GetValue(8)?.ToString();
                        var foundUtc = GetSafeDateTime(refReader, 9);

                        var repoDto = new ApiHunterRepoSourceDto(
                            refId, keyId, repoUrl, repoOwner, repoName, filePath, fileUrl, lineNum, codeCtx, foundUtc);

                        if (keyMap.TryGetValue(keyId, out var keyDto))
                        {
                            keyDto.References.Add(repoDto);
                        }
                    }
                    catch (Exception refEx)
                    {
                        _logger.LogWarning(refEx, "Failed to parse individual RepoReference record row.");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute read-only query against APIHunter database. Exception: {Message}", ex.Message);
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

    private static async Task<(string keysTable, string refsTable)> ResolveTableNamesAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        try
        {
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';";
            var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await using (var reader = await cmd.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    tables.Add(reader.GetString(0));
                }
            }

            string keysTable = tables.Contains("APIKeys") ? "\"APIKeys\"" :
                               tables.Contains("apikeys") ? "\"apikeys\"" :
                               tables.Contains("api_keys") ? "\"api_keys\"" :
                               tables.Contains("api_hunter_records") ? "\"api_hunter_records\"" : "\"APIKeys\"";

            string refsTable = tables.Contains("RepoReferences") ? "\"RepoReferences\"" :
                               tables.Contains("reporeferences") ? "\"reporeferences\"" :
                               tables.Contains("repo_references") ? "\"repo_references\"" :
                               tables.Contains("api_hunter_repo_references") ? "\"api_hunter_repo_references\"" : "\"RepoReferences\"";

            return (keysTable, refsTable);
        }
        catch
        {
            return ("\"APIKeys\"", "\"RepoReferences\"");
        }
    }

    private static int GetSafeInt(NpgsqlDataReader reader, int index, int defaultValue = -99)
    {
        if (reader.IsDBNull(index)) return defaultValue;
        try
        {
            var val = reader.GetValue(index);
            return Convert.ToInt32(val);
        }
        catch
        {
            return defaultValue;
        }
    }

    private static long GetSafeLong(NpgsqlDataReader reader, int index, long defaultValue = 0)
    {
        if (reader.IsDBNull(index)) return defaultValue;
        try
        {
            var val = reader.GetValue(index);
            return Convert.ToInt64(val);
        }
        catch
        {
            return defaultValue;
        }
    }

    private static DateTime GetSafeDateTime(NpgsqlDataReader reader, int index)
    {
        if (reader.IsDBNull(index)) return DateTime.UtcNow;
        try
        {
            var val = reader.GetValue(index);
            if (val is DateTime dt) return dt.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(dt, DateTimeKind.Utc) : dt.ToUniversalTime();
            if (val is DateTimeOffset dto) return dto.UtcDateTime;
            if (DateTime.TryParse(val?.ToString(), out var parsed)) return DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
        }
        catch { }
        return DateTime.UtcNow;
    }
}


