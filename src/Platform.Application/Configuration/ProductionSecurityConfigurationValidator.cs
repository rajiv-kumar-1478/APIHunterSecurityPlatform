using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Platform.Domain.Enums;

namespace Platform.Application.Configuration;

/// <summary>
/// Exception thrown when production security configuration invariants are violated.
/// </summary>
public sealed class ProductionSecurityConfigurationException : Exception
{
    public IReadOnlyList<string> Violations { get; }

    public ProductionSecurityConfigurationException(IReadOnlyList<string> violations)
        : base($"Production security configuration validation failed with {violations.Count} violation(s):\n - " + string.Join("\n - ", violations))
    {
        Violations = violations;
    }
}

/// <summary>
/// Authoritative validator that ensures all critical production security settings,
/// network isolation policies, data protection key stores, and scanner sandboxes
/// are strictly configured before the host process can start in Production mode.
/// </summary>
public sealed class ProductionSecurityConfigurationValidator
{
    public static void Validate(IConfiguration configuration)
    {
        var validator = new ProductionSecurityConfigurationValidator();
        validator.ValidateConfiguration(configuration);
    }

    public void ValidateConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var violations = new List<string>();

        // 1. HTTPS Requirement
        var requireHttpsStr = configuration["Authentication:RequireHttps"];
        if (string.IsNullOrWhiteSpace(requireHttpsStr) || !bool.TryParse(requireHttpsStr, out var requireHttps) || !requireHttps)
        {
            violations.Add("Authentication:RequireHttps must be explicitly set to 'true' in Production.");
        }

        // 2. Database Connection String
        var dbConn = configuration["Database:ConnectionString"] ?? configuration.GetConnectionString("Default");
        if (string.IsNullOrWhiteSpace(dbConn))
        {
            violations.Add("Database:ConnectionString is required in Production and cannot be empty.");
        }
        else if (dbConn.Trim().Equals("InMemory", StringComparison.OrdinalIgnoreCase) ||
                 dbConn.Contains("PlatformTestDb", StringComparison.OrdinalIgnoreCase))
        {
            violations.Add("Database:ConnectionString cannot use InMemory or Test providers in Production.");
        }

        // 3. Data Protection Key Persistence
        var dpKeyPath = configuration["DataProtection:KeyPath"];
        if (string.IsNullOrWhiteSpace(dpKeyPath))
        {
            violations.Add("DataProtection:KeyPath is required in Production to ensure persistent cryptographic keys across process restarts.");
        }

        // 4. Scanner Runtime & Sandbox Mode
        var runtimeModeStr = configuration["ScannerRuntime:RuntimeMode"] ?? "LocalDocker";
        if (!Enum.TryParse<ScannerRuntimeMode>(runtimeModeStr, ignoreCase: true, out var runtimeMode))
        {
            violations.Add($"ScannerRuntime:RuntimeMode '{runtimeModeStr}' is invalid.");
        }
        else if (runtimeMode == ScannerRuntimeMode.UnsafeLocalProcessFallback)
        {
            violations.Add("ScannerRuntime:RuntimeMode cannot be 'UnsafeLocalProcessFallback' in Production.");
        }
        else if (runtimeMode == ScannerRuntimeMode.CloudManagedContainer)
        {
            var hostedEndpoint = configuration["ScannerRuntime:HostedScannerServiceEndpoint"];
            var hostedKey = configuration["ScannerRuntime:HostedScannerServiceKey"];

            if (string.IsNullOrWhiteSpace(hostedEndpoint) || !Uri.TryCreate(hostedEndpoint, UriKind.Absolute, out _))
            {
                violations.Add("ScannerRuntime:HostedScannerServiceEndpoint is required and must be a valid absolute URI when CloudManagedContainer is selected.");
            }

            if (string.IsNullOrWhiteSpace(hostedKey))
            {
                violations.Add("ScannerRuntime:HostedScannerServiceKey is required when CloudManagedContainer is selected.");
            }
        }
        else // LocalDocker
        {
            var requireDockerSandboxStr = configuration["ScannerRuntime:RequireDockerSandbox"];
            if (string.IsNullOrWhiteSpace(requireDockerSandboxStr) || !bool.TryParse(requireDockerSandboxStr, out var requireDocker) || !requireDocker)
            {
                violations.Add("ScannerRuntime:RequireDockerSandbox must be set to 'true' in Production.");
            }
        }

        // 5. Image Provenance & Trusted Registries
        var enforceProvenanceStr = configuration["ScannerRuntime:EnforceImageProvenance"] ?? "true";
        if (bool.TryParse(enforceProvenanceStr, out var enforceProvenance) && !enforceProvenance)
        {
            violations.Add("ScannerRuntime:EnforceImageProvenance cannot be disabled in Production.");
        }

        var trustedRegistries = configuration.GetSection("ScannerRuntime:TrustedImageRegistries").Get<string[]>() ?? [];
        if (trustedRegistries.Length == 0)
        {
            violations.Add("ScannerRuntime:TrustedImageRegistries must contain at least one trusted container registry in Production.");
        }

        // 6. Egress Gateway & Network Isolation
        var egressModeStr = configuration["ScannerRuntime:EgressGatewayMode"] ?? "EnforcedGateway";
        if (!Enum.TryParse<EgressGatewayMode>(egressModeStr, ignoreCase: true, out var egressMode) || egressMode != EgressGatewayMode.EnforcedGateway)
        {
            violations.Add("ScannerRuntime:EgressGatewayMode must be 'EnforcedGateway' in Production.");
        }

        var egressEndpoint = configuration["ScannerRuntime:EgressGatewayEndpoint"];
        if (string.IsNullOrWhiteSpace(egressEndpoint) || !Uri.TryCreate(egressEndpoint, UriKind.Absolute, out _))
        {
            violations.Add("ScannerRuntime:EgressGatewayEndpoint is required and must be a valid absolute URI.");
        }

        var egressNet = configuration["ScannerRuntime:EgressNetworkName"];
        if (string.IsNullOrWhiteSpace(egressNet))
        {
            violations.Add("ScannerRuntime:EgressNetworkName is required in Production.");
        }

        // 7. Unsafe fallback check
        var allowUnsafeStr = configuration["ScannerRuntime:AllowUnsafeProcessFallback"];
        if (bool.TryParse(allowUnsafeStr, out var allowUnsafe) && allowUnsafe)
        {
            violations.Add("ScannerRuntime:AllowUnsafeProcessFallback must be 'false' in Production.");
        }

        if (violations.Count > 0)
        {
            throw new ProductionSecurityConfigurationException(violations);
        }
    }
}
