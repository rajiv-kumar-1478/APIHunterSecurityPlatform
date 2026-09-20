using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Platform.Api.Services;

public class EnvironmentValidationHostedService(
    IConfiguration configuration,
    IHostEnvironment environment,
    ILogger<EnvironmentValidationHostedService> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Executing platform production security & environment verification...");

        var issues = new List<string>();

        // 1. Connection string verification
        var connStr = configuration["Database:ConnectionString"] ?? configuration.GetConnectionString("Default");
        if (string.IsNullOrWhiteSpace(connStr) && !environment.IsEnvironment("Testing"))
        {
            issues.Add("Database connection string is missing or empty.");
        }

        // 2. Encryption / Data Protection Secret Entropy
        var masterKey = configuration["Security:MasterEncryptionKey"] ?? configuration["DataProtection:MasterKey"];
        if (environment.IsProduction())
        {
            if (string.IsNullOrWhiteSpace(masterKey))
            {
                issues.Add("Production requires 'Security:MasterEncryptionKey' to be configured.");
            }
            else if (Encoding.UTF8.GetByteCount(masterKey) < 32)
            {
                issues.Add($"Security:MasterEncryptionKey has insufficient entropy ({Encoding.UTF8.GetByteCount(masterKey)} bytes; minimum 32 bytes / 256-bit required).");
            }

            // 3. JWT Signing Key Entropy
            var jwtKey = configuration["Authentication:JwtSecret"] ?? configuration["Jwt:Secret"];
            if (!string.IsNullOrWhiteSpace(jwtKey) && Encoding.UTF8.GetByteCount(jwtKey) < 32)
            {
                issues.Add("Authentication JWT secret must be at least 256 bits (32 bytes) in Production.");
            }
        }

        if (issues.Count > 0)
        {
            var errorMessage = "FATAL: Production Security Configuration Gate Failed:\n- " + string.Join("\n- ", issues);
            logger.LogCritical("{Message}", errorMessage);

            if (environment.IsProduction())
            {
                throw new InvalidOperationException(errorMessage);
            }
            else
            {
                logger.LogWarning("Running with non-production warnings:\n- {Warnings}", string.Join("\n- ", issues));
            }
        }
        else
        {
            logger.LogInformation("Security & Environment configuration gate passed successfully.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
