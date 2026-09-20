using System;
using Npgsql;

namespace Platform.Infrastructure.Persistence;

/// <summary>
/// Converts PostgreSQL connection URLs (postgres:// or postgresql://) commonly provided by cloud PaaS
/// platforms (Aiven, Supabase, Render, Neon, Heroku) into standard Npgsql key-value connection strings.
/// </summary>
public static class PostgresConnectionStringNormalizer
{
    public static string Normalize(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
            return string.Empty;

        var trimmed = connectionString.Trim();

        if (trimmed.Equals("InMemory", StringComparison.OrdinalIgnoreCase))
            return "InMemory";

        // Check if connection string is in URI format: postgres:// or postgresql://
        if (trimmed.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var uri = new Uri(trimmed);
                var builder = new NpgsqlConnectionStringBuilder();

                if (!string.IsNullOrEmpty(uri.Host))
                {
                    builder.Host = uri.Host;
                }

                if (uri.Port > 0)
                {
                    builder.Port = uri.Port;
                }

                var dbName = uri.AbsolutePath.TrimStart('/');
                if (!string.IsNullOrEmpty(dbName))
                {
                    builder.Database = dbName;
                }

                if (!string.IsNullOrEmpty(uri.UserInfo))
                {
                    var userParts = uri.UserInfo.Split(':', 2);
                    builder.Username = Uri.UnescapeDataString(userParts[0]);
                    if (userParts.Length > 1)
                    {
                        builder.Password = Uri.UnescapeDataString(userParts[1]);
                    }
                }

                // Default SSL Mode to Require for cloud PostgreSQL (Aiven, Supabase, Neon, Render)
                builder.SslMode = SslMode.Require;

                // Parse query parameters if present (e.g. sslmode=disable, sslmode=require)
                if (!string.IsNullOrEmpty(uri.Query))
                {
                    var query = uri.Query.TrimStart('?');
                    var pairs = query.Split('&', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var pair in pairs)
                    {
                        var kv = pair.Split('=', 2);
                        var key = kv[0].ToLowerInvariant();
                        var val = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : string.Empty;

                        if (key == "sslmode")
                        {
                            if (val.Equals("disable", StringComparison.OrdinalIgnoreCase))
                                builder.SslMode = SslMode.Disable;
                            else if (val.Equals("allow", StringComparison.OrdinalIgnoreCase))
                                builder.SslMode = SslMode.Allow;
                            else if (val.Equals("prefer", StringComparison.OrdinalIgnoreCase))
                                builder.SslMode = SslMode.Prefer;
                            else if (val.Equals("require", StringComparison.OrdinalIgnoreCase))
                                builder.SslMode = SslMode.Require;
                            else if (val.Equals("verify-ca", StringComparison.OrdinalIgnoreCase))
                                builder.SslMode = SslMode.VerifyCA;
                            else if (val.Equals("verify-full", StringComparison.OrdinalIgnoreCase))
                                builder.SslMode = SslMode.VerifyFull;
                        }
                    }
                }

                // If using Supabase transaction pooler (6543) or Supabase pooler, disable auto prepare for PgBouncer compatibility
                if (builder.Port == 6543 || (builder.Host != null && builder.Host.Contains("pooler.supabase.com", StringComparison.OrdinalIgnoreCase)))
                {
                    builder.MaxPoolSize = 10;
                    builder.Multiplexing = false;
                }

                return builder.ConnectionString;
            }
            catch
            {
                // Return original string if Uri parsing fails
                return trimmed;
            }
        }

        return trimmed;
    }
}
