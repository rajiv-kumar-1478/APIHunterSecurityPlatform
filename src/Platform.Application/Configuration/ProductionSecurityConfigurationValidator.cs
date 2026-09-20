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
/// Validates production database, cryptographic key, scanner isolation, and
/// web-host HTTPS invariants before a process starts.
/// </summary>
public sealed class ProductionSecurityConfigurationValidator
{
    public static void Validate(IConfiguration configuration, bool requireHttps = true)
    {
        var validator = new ProductionSecurityConfigurationValidator();
        validator.ValidateConfiguration(configuration, requireHttps);
    }

    public void ValidateConfiguration(IConfiguration configuration, bool requireHttps = true)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var violations = new List<string>();

        if (requireHttps)
        {
            var requireHttpsValue = configuration["Authentication:RequireHttps"];
            if (string.IsNullOrWhiteSpace(requireHttpsValue) ||
                !bool.TryParse(requireHttpsValue, out var httpsRequired) ||
                !httpsRequired)
            {
                violations.Add("Authentication:RequireHttps must be explicitly set to 'true' for a Production web host.");
            }
        }

        if (!Guid.TryParse(configuration["Tenant:Id"], out var tenantId) || tenantId == Guid.Empty)
        {
            violations.Add("Tenant:Id is required in Production and must be a non-empty GUID.");
        }

        var databaseConnection = configuration["Database:ConnectionString"]
            ?? configuration.GetConnectionString("Default")
            ?? configuration["DATABASE_URL"];
        if (string.IsNullOrWhiteSpace(databaseConnection))
        {
            violations.Add("Database:ConnectionString is required in Production and cannot be empty.");
        }
        else if (databaseConnection.Trim().Equals("InMemory", StringComparison.OrdinalIgnoreCase) ||
                 databaseConnection.Contains("PlatformTestDb", StringComparison.OrdinalIgnoreCase))
        {
            violations.Add("Database:ConnectionString cannot use InMemory or Test providers in Production.");
        }

        if (string.IsNullOrWhiteSpace(configuration["DataProtection:KeyPath"]))
        {
            violations.Add("DataProtection:KeyPath is required in Production to ensure persistent cryptographic keys across process restarts.");
        }

        if (string.IsNullOrWhiteSpace(configuration["DataProtection:ApplicationName"]))
        {
            violations.Add("DataProtection:ApplicationName is required in Production so API and worker hosts share the same key-ring discriminator.");
        }

        var runtimeModeValue = configuration["ScannerRuntime:RuntimeMode"] ?? "Disabled";
        if (!Enum.TryParse<ScannerRuntimeMode>(runtimeModeValue, ignoreCase: true, out var runtimeMode))
        {
            violations.Add($"ScannerRuntime:RuntimeMode '{runtimeModeValue}' is invalid.");
        }
        else if (runtimeMode == ScannerRuntimeMode.Disabled)
        {
            ValidateDisabledScannerConfiguration(configuration, violations);
        }
        else
        {
            ValidateEnabledScannerConfiguration(configuration, runtimeMode, violations);
        }

        if (bool.TryParse(configuration["ScannerRuntime:AllowUnsafeProcessFallback"], out var unsafeFallback) && unsafeFallback)
        {
            violations.Add("ScannerRuntime:AllowUnsafeProcessFallback must be 'false' in Production.");
        }

        if (violations.Count > 0)
        {
            throw new ProductionSecurityConfigurationException(violations);
        }
    }

    private static void ValidateDisabledScannerConfiguration(
        IConfiguration configuration,
        ICollection<string> violations)
    {
        var egressModeValue = configuration["ScannerRuntime:EgressGatewayMode"] ?? "None";
        if (!Enum.TryParse<EgressGatewayMode>(egressModeValue, ignoreCase: true, out var egressMode) ||
            egressMode != EgressGatewayMode.None)
        {
            violations.Add("ScannerRuntime:EgressGatewayMode must be 'None' when ScannerRuntime:RuntimeMode is 'Disabled'.");
        }

        if (!string.IsNullOrWhiteSpace(configuration["ScannerRuntime:EgressGatewayEndpoint"]))
        {
            violations.Add("ScannerRuntime:EgressGatewayEndpoint must be empty when the scanner runtime is disabled.");
        }

        if (!string.IsNullOrWhiteSpace(configuration["ScannerRuntime:EgressNetworkName"]))
        {
            violations.Add("ScannerRuntime:EgressNetworkName must be empty when the scanner runtime is disabled.");
        }

        if (IsExplicitlyEnabled(configuration["ScanJobConsumer:Enabled"]))
        {
            violations.Add("ScanJobConsumer:Enabled must be 'false' when the scanner runtime is disabled.");
        }

        if (IsExplicitlyEnabled(configuration["CampaignScheduler:GlobalEnabled"]))
        {
            violations.Add("CampaignScheduler:GlobalEnabled must be 'false' when the scanner runtime is disabled.");
        }
    }

    private static void ValidateEnabledScannerConfiguration(
        IConfiguration configuration,
        ScannerRuntimeMode runtimeMode,
        ICollection<string> violations)
    {
        if (runtimeMode == ScannerRuntimeMode.UnsafeLocalProcessFallback)
        {
            violations.Add("ScannerRuntime:RuntimeMode cannot be 'UnsafeLocalProcessFallback' in Production.");
        }
        else if (runtimeMode == ScannerRuntimeMode.CloudManagedContainer)
        {
            var hostedEndpoint = configuration["ScannerRuntime:HostedScannerServiceEndpoint"];
            if (string.IsNullOrWhiteSpace(hostedEndpoint) ||
                !Uri.TryCreate(hostedEndpoint, UriKind.Absolute, out _))
            {
                violations.Add("ScannerRuntime:HostedScannerServiceEndpoint is required and must be a valid absolute URI when CloudManagedContainer is selected.");
            }

            if (string.IsNullOrWhiteSpace(configuration["ScannerRuntime:HostedScannerServiceKey"]))
            {
                violations.Add("ScannerRuntime:HostedScannerServiceKey is required when CloudManagedContainer is selected.");
            }
        }
        else if (!IsExplicitlyEnabled(configuration["ScannerRuntime:RequireDockerSandbox"]))
        {
            violations.Add("ScannerRuntime:RequireDockerSandbox must be set to 'true' in Production.");
        }

        var provenanceValue = configuration["ScannerRuntime:EnforceImageProvenance"] ?? "true";
        if (!bool.TryParse(provenanceValue, out var provenanceEnabled) || !provenanceEnabled)
        {
            violations.Add("ScannerRuntime:EnforceImageProvenance must be 'true' in Production.");
        }

        var trustedRegistries = configuration
            .GetSection("ScannerRuntime:TrustedImageRegistries")
            .Get<string[]>() ?? [];
        if (trustedRegistries.Length == 0)
        {
            violations.Add("ScannerRuntime:TrustedImageRegistries must contain at least one trusted container registry in Production.");
        }

        var egressModeValue = configuration["ScannerRuntime:EgressGatewayMode"] ?? "EnforcedGateway";
        if (!Enum.TryParse<EgressGatewayMode>(egressModeValue, ignoreCase: true, out var egressMode) ||
            egressMode != EgressGatewayMode.EnforcedGateway)
        {
            violations.Add("ScannerRuntime:EgressGatewayMode must be 'EnforcedGateway' in Production.");
        }

        var egressEndpoint = configuration["ScannerRuntime:EgressGatewayEndpoint"];
        if (string.IsNullOrWhiteSpace(egressEndpoint) ||
            !Uri.TryCreate(egressEndpoint, UriKind.Absolute, out _))
        {
            violations.Add("ScannerRuntime:EgressGatewayEndpoint is required and must be a valid absolute URI.");
        }

        if (string.IsNullOrWhiteSpace(configuration["ScannerRuntime:EgressNetworkName"]))
        {
            violations.Add("ScannerRuntime:EgressNetworkName is required in Production.");
        }
    }

    private static bool IsExplicitlyEnabled(string? value) =>
        bool.TryParse(value, out var enabled) && enabled;
}
