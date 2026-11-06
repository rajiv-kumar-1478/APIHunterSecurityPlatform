using Microsoft.Extensions.Configuration;
using Platform.Application.Configuration;
using Platform.Infrastructure.Persistence;

namespace Platform.Infrastructure.Adapters.ApiHunter;

internal static class ApiHunterConnectionStringResolver
{
    public static string Resolve(IConfiguration configuration, ApiHunterSourceOptions options)
    {
        var raw = !string.IsNullOrWhiteSpace(options.ConnectionString)
            ? options.ConnectionString
            : configuration["APIHUNTER_DATABASE_URL"]
              ?? configuration["ApiHunterSource:ConnectionString"]
              ?? configuration["ApiHunterSource__ConnectionString"]
              ?? configuration["Database:ConnectionString"]
              ?? configuration["ConnectionStrings:Default"]
              ?? configuration["DATABASE_URL"];

        return PostgresConnectionStringNormalizer.Normalize(raw);
    }
}
