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
    private readonly IApiHunterStatusMapper _statusMapper;

    public ApiHunterAdapter(
        IOptions<ApiHunterSourceOptions> options,
        IConfiguration configuration,
        ILogger<ApiHunterAdapter> logger,
        IApiHunterStatusMapper? statusMapper = null)
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
        _statusMapper = statusMapper ?? new ApiHunterStatusMapper();
    }

    public async Task<ApiHunterSourceSummaryDto> GetSummaryAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_connectionString))
        {
            return new ApiHunterSourceSummaryDto(0, 0, 0, 0, false);
        }

        long totalKeys = 0;
        long validKeys = 0;
        long validNoCredits = 0;
        long totalRepos = 0;
        bool connected = false;

        try
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync(ct);
            connected = true;

            var (keysTable, refsTable) = await ResolveTableNamesAsync(conn, ct);

            try
            {
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = $@"
                    SELECT 
                        COUNT(*) as TotalKeys,
                        SUM(CASE WHEN ""Status"" = 1 THEN 1 ELSE 0 END) as ValidKeys,
                        SUM(CASE WHEN ""Status"" = 7 THEN 1 ELSE 0 END) as ValidNoCreditsKeys
                    FROM {keysTable};";

                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (await reader.ReadAsync(ct))
                {
                    totalKeys = GetSafeLong(reader, 0);
                    validKeys = GetSafeLong(reader, 1);
                    validNoCredits = GetSafeLong(reader, 2);
                }
            }
            catch (Exception keyEx)
            {
                _logger.LogWarning(keyEx, "Failed to query keys table from APIHunter source database.");
            }

            try
            {
                await using var refCmd = conn.CreateCommand();
                refCmd.CommandText = $"SELECT COUNT(*) FROM {refsTable};";
                var refRes = await refCmd.ExecuteScalarAsync(ct);
                if (refRes != null && refRes != DBNull.Value)
                {
                    totalRepos = Convert.ToInt64(refRes);
                }
            }
            catch (Exception refEx)
            {
                _logger.LogWarning(refEx, "Failed to query repo references table from APIHunter source database.");
            }

            return new ApiHunterSourceSummaryDto(totalKeys, validKeys, validNoCredits, totalRepos, connected);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect or fetch summary from APIHunter source database. Exception: {Message}", ex.Message);
        }

        return new ApiHunterSourceSummaryDto(0, 0, 0, 0, connected);
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

            // Fetch keys batch prioritizing Valid (1) and ValidNoCredits (7) keys first (excluding Invalid keys where Status = 0)
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $@"
                SELECT ""Id"", ""ApiKey"", ""Status"", ""ApiType"", ""SearchProvider"", ""LastCheckedUTC"", 
                       ""FirstFoundUTC"", ""LastFoundUTC"", ""ValidationResponse"", ""Balance"", ""AccountTier"", 
                       ""AwsAccountId"", ""AwsRiskLevel""
                FROM {keysTable}
                WHERE ""Id"" > @lastSyncedId AND ""Status"" <> 0
                ORDER BY CASE 
                    WHEN ""Status"" = 1 THEN 1 
                    WHEN ""Status"" = 7 THEN 2 
                    WHEN ""Status"" = 6 THEN 3 
                    ELSE 4 
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

    public async Task<ApiHunterKeyDetailsDto?> GetKeyDetailsAsync(long keyId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_connectionString)) return null;

        try
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync(ct);

            var (keysTable, refsTable) = await ResolveTableNamesAsync(conn, ct);

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $@"
                SELECT ""Id"", ""ApiKey"", ""Status"", ""ApiType"", ""SearchProvider"", ""LastCheckedUTC"", 
                       ""FirstFoundUTC"", ""LastFoundUTC"", ""TimesDisplayed"", ""ErrorCount"", ""ValidationResponse"", 
                       ""Balance"", ""AccountTier"", ""DiscoveredByTelegramId"", ""Metadata"",
                       ""AwsAccountId"", ""AwsUserArn"", ""AwsUserId"", ""AwsCredentialType"", ""AwsAttachedPolicies"", 
                       ""AwsRiskLevel"", ""AwsIsRootAccount""
                FROM {keysTable}
                WHERE ""Id"" = @keyId
                LIMIT 1;";

            cmd.Parameters.AddWithValue("keyId", keyId);

            ApiHunterKeyDetailsDto? dto = null;
            await using (var reader = await cmd.ExecuteReaderAsync(ct))
            {
                if (await reader.ReadAsync(ct))
                {
                    var apiKey = reader.IsDBNull(1) ? string.Empty : reader.GetValue(1)?.ToString() ?? string.Empty;
                    var statusInt = GetSafeInt(reader, 2, -99);
                    var apiTypeInt = GetSafeInt(reader, 3, -99);
                    var providerInt = GetSafeInt(reader, 4, 0);
                    var lastChecked = reader.IsDBNull(5) ? (DateTime?)null : GetSafeDateTime(reader, 5);
                    var firstFound = GetSafeDateTime(reader, 6);
                    var lastFound = GetSafeDateTime(reader, 7);
                    var timesDisplayed = GetSafeInt(reader, 8, 0);
                    var errorCount = GetSafeInt(reader, 9, 0);
                    var validationResponse = reader.IsDBNull(10) ? null : reader.GetValue(10)?.ToString();
                    var balance = reader.IsDBNull(11) ? null : reader.GetValue(11)?.ToString();
                    var accountTier = reader.IsDBNull(12) ? null : reader.GetValue(12)?.ToString();
                    var telegramId = reader.IsDBNull(13) ? (long?)null : GetSafeLong(reader, 13);
                    var metadata = reader.IsDBNull(14) ? null : reader.GetValue(14)?.ToString();

                    var awsAccountId = reader.IsDBNull(15) ? null : reader.GetValue(15)?.ToString();
                    var awsUserArn = reader.IsDBNull(16) ? null : reader.GetValue(16)?.ToString();
                    var awsUserId = reader.IsDBNull(17) ? null : reader.GetValue(17)?.ToString();
                    var awsCredType = reader.IsDBNull(18) ? null : reader.GetValue(18)?.ToString();
                    var awsPolicies = reader.IsDBNull(19) ? null : reader.GetValue(19)?.ToString();
                    var awsRiskLevel = reader.IsDBNull(20) ? null : reader.GetValue(20)?.ToString();
                    var awsIsRoot = !reader.IsDBNull(21) && reader.GetBoolean(21);

                    ApiHunterAwsMetadataDto? awsMetadata = null;
                    if (!string.IsNullOrEmpty(awsAccountId) || !string.IsNullOrEmpty(awsUserArn) || !string.IsNullOrEmpty(awsRiskLevel) || awsIsRoot)
                    {
                        awsMetadata = new ApiHunterAwsMetadataDto(awsAccountId, awsUserArn, awsUserId, awsCredType, awsPolicies, awsRiskLevel, awsIsRoot);
                    }

                    var apiTypeName = _statusMapper.MapApiType(apiTypeInt);
                    var statusDomain = _statusMapper.MapStatus(statusInt);
                    var statusName = statusDomain.ToString();
                    var searchProvider = providerInt == 1 ? "GitHub" : (providerInt == 0 ? "GitHub" : $"Provider_{providerInt}");

                    var firstFoundUtc = firstFound.Kind == DateTimeKind.Utc ? firstFound : DateTime.SpecifyKind(firstFound, DateTimeKind.Utc);
                    var firstFoundIst = firstFoundUtc.AddHours(5).AddMinutes(30).ToString("yyyy-MM-dd HH:mm:ss");

                    string? lastCheckedIst = null;
                    if (lastChecked.HasValue)
                    {
                        var lastCheckedUtc = lastChecked.Value.Kind == DateTimeKind.Utc ? lastChecked.Value : DateTime.SpecifyKind(lastChecked.Value, DateTimeKind.Utc);
                        lastCheckedIst = lastCheckedUtc.AddHours(5).AddMinutes(30).ToString("yyyy-MM-dd HH:mm:ss");
                    }

                    dto = new ApiHunterKeyDetailsDto(
                        ApiKey: apiKey,
                        ApiTypeName: apiTypeName,
                        Status: statusInt,
                        StatusName: statusName,
                        SearchProvider: searchProvider,
                        Balance: balance,
                        AccountTier: accountTier,
                        FirstFoundUTC: firstFound,
                        LastFoundUTC: lastFound,
                        LastCheckedUTC: lastChecked,
                        ErrorCount: errorCount,
                        FirstFoundIST: firstFoundIst,
                        LastCheckedIST: lastCheckedIst,
                        TimesDisplayed: timesDisplayed,
                        ValidationResponse: validationResponse,
                        Metadata: metadata,
                        DiscoveredByTelegramId: telegramId,
                        AwsMetadata: awsMetadata,
                        Sources: new List<ApiHunterSourceReferenceDto>());
                }
            }

            if (dto != null)
            {
                await using var refCmd = conn.CreateCommand();
                refCmd.CommandText = $@"
                    SELECT ""RepoURL"", ""FileURL"", ""FoundUTC""
                    FROM {refsTable}
                    WHERE ""APIKeyId"" = @keyId;";
                refCmd.Parameters.AddWithValue("keyId", keyId);

                await using var refReader = await refCmd.ExecuteReaderAsync(ct);
                while (await refReader.ReadAsync(ct))
                {
                    var repoUrl = refReader.IsDBNull(0) ? null : refReader.GetValue(0)?.ToString();
                    var fileUrl = refReader.IsDBNull(1) ? null : refReader.GetValue(1)?.ToString();
                    var foundUtc = GetSafeDateTime(refReader, 2);
                    var sourceUrl = !string.IsNullOrWhiteSpace(fileUrl) ? fileUrl : (repoUrl ?? string.Empty);
                    if (!string.IsNullOrWhiteSpace(sourceUrl))
                    {
                        dto.Sources.Add(new ApiHunterSourceReferenceDto(sourceUrl, foundUtc));
                    }
                }
            }

            return dto;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch key details for APIHunter key ID {KeyId}", keyId);
            return null;
        }
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


