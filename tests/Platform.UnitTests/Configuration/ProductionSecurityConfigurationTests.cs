using System;
using System.Collections.Generic;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Platform.Application.Configuration;
using Xunit;

namespace Platform.UnitTests.Configuration;

public class ProductionSecurityConfigurationTests
{
    private static Dictionary<string, string?> CreateValidProductionSettings() => new()
    {
        ["Authentication:RequireHttps"] = "true",
        ["Tenant:Id"] = "11111111-1111-1111-1111-111111111111",
        ["Database:ConnectionString"] = "Host=prod-pg.internal;Database=apihunter;Username=api_user;Password=StrongSecretPassword123!",
        ["DataProtection:KeyPath"] = "/var/secrets/dp-keys",
        ["DataProtection:ApplicationName"] = "APIHunterPlatform",
        ["ScannerRuntime:RuntimeMode"] = "LocalDocker",
        ["ScannerRuntime:RequireDockerSandbox"] = "true",
        ["ScannerRuntime:EnforceImageProvenance"] = "true",
        ["ScannerRuntime:TrustedImageRegistries:0"] = "ghcr.io/apihunter-security",
        ["ScannerRuntime:TrustedImageRegistries:1"] = "docker.io/apihunter",
        ["ScannerRuntime:EgressGatewayMode"] = "EnforcedGateway",
        ["ScannerRuntime:EgressGatewayEndpoint"] = "http://10.0.0.10:8888",
        ["ScannerRuntime:EgressNetworkName"] = "apihunter-sandbox-net",
        ["ScannerRuntime:AllowUnsafeProcessFallback"] = "false"
    };

    private static IConfiguration BuildConfiguration(Dictionary<string, string?> settings)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();
    }

    [Fact]
    public void FullyConfiguredProduction_Passes()
    {
        var config = BuildConfiguration(CreateValidProductionSettings());

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void MissingOrInvalidTenantId_Fails(string? tenantId)
    {
        var settings = CreateValidProductionSettings();
        settings["Tenant:Id"] = tenantId;
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("Tenant:Id"));
    }

    [Fact]
    public void WorkerValidation_StillRequiresTenantId()
    {
        var settings = CreateValidProductionSettings();
        settings["Tenant:Id"] = "";

        var act = () => ProductionSecurityConfigurationValidator.Validate(
            BuildConfiguration(settings),
            requireHttps: false);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("Tenant:Id"));
    }

    [Fact]
    public void MissingHttpsConfiguration_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["Authentication:RequireHttps"] = "false";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("Authentication:RequireHttps"));
    }

    [Fact]
    public void MissingDatabaseConfiguration_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["Database:ConnectionString"] = "";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("Database:ConnectionString"));
    }

    [Theory]
    [InlineData("InMemory")]
    [InlineData("PlatformTestDb")]
    public void InMemoryDatabase_InProduction_Fails(string testDbConn)
    {
        var settings = CreateValidProductionSettings();
        settings["Database:ConnectionString"] = testDbConn;
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("cannot use InMemory or Test providers"));
    }

    [Fact]
    public void EphemeralDataProtectionKeys_Fail()
    {
        var settings = CreateValidProductionSettings();
        settings["DataProtection:KeyPath"] = "";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("DataProtection:KeyPath"));
    }

    [Fact]
    public void MissingSandboxConfiguration_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:RequireDockerSandbox"] = "false";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("ScannerRuntime:RequireDockerSandbox"));
    }

    [Fact]
    public void UnsafeLocalProcessFallback_InProduction_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:RuntimeMode"] = "UnsafeLocalProcessFallback";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("UnsafeLocalProcessFallback"));
    }

    [Fact]
    public void AllowUnsafeProcessFallback_True_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:AllowUnsafeProcessFallback"] = "true";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("AllowUnsafeProcessFallback"));
    }

    [Fact]
    public void CloudManagedContainer_ValidEndpointAndKey_Passes()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:RuntimeMode"] = "CloudManagedContainer";
        settings["ScannerRuntime:HostedScannerServiceEndpoint"] = "https://cloud-scanner.internal:9443";
        settings["ScannerRuntime:HostedScannerServiceKey"] = "sec-hosted-key-prod-993821";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        act.Should().NotThrow();
    }

    [Fact]
    public void CloudManagedContainer_MissingEndpointOrKey_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:RuntimeMode"] = "CloudManagedContainer";
        settings["ScannerRuntime:HostedScannerServiceEndpoint"] = "";
        settings["ScannerRuntime:HostedScannerServiceKey"] = "";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("HostedScannerServiceEndpoint"));
        ex.Violations.Should().Contain(v => v.Contains("HostedScannerServiceKey"));
    }

    [Fact]
    public void MissingEgressGateway_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:EgressGatewayMode"] = "None";
        settings["ScannerRuntime:EgressGatewayEndpoint"] = "";
        settings["ScannerRuntime:EgressNetworkName"] = "";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("EgressGatewayMode"));
        ex.Violations.Should().Contain(v => v.Contains("EgressGatewayEndpoint"));
        ex.Violations.Should().Contain(v => v.Contains("EgressNetworkName"));
    }

    [Fact]
    public void DisabledImageProvenance_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:EnforceImageProvenance"] = "false";
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("EnforceImageProvenance"));
    }

    [Fact]
    public void EmptyTrustedImageRegistries_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings.Remove("ScannerRuntime:TrustedImageRegistries:0");
        settings.Remove("ScannerRuntime:TrustedImageRegistries:1");
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Should().Contain(v => v.Contains("TrustedImageRegistries"));
    }

    [Fact]
    public void DisabledScanner_WithConsumersAndCampaignsOff_Passes()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:RuntimeMode"] = "Disabled";
        settings["ScannerRuntime:EgressGatewayMode"] = "None";
        settings["ScannerRuntime:EgressGatewayEndpoint"] = "";
        settings["ScannerRuntime:EgressNetworkName"] = "";
        settings["ScanJobConsumer:Enabled"] = "false";
        settings["CampaignScheduler:GlobalEnabled"] = "false";

        var act = () => ProductionSecurityConfigurationValidator.Validate(BuildConfiguration(settings));

        act.Should().NotThrow();
    }

    [Fact]
    public void DisabledScanner_WithExecutionConsumerEnabled_Fails()
    {
        var settings = CreateValidProductionSettings();
        settings["ScannerRuntime:RuntimeMode"] = "Disabled";
        settings["ScannerRuntime:EgressGatewayMode"] = "None";
        settings["ScannerRuntime:EgressGatewayEndpoint"] = "";
        settings["ScannerRuntime:EgressNetworkName"] = "";
        settings["ScanJobConsumer:Enabled"] = "true";

        var act = () => ProductionSecurityConfigurationValidator.Validate(BuildConfiguration(settings));

        act.Should().Throw<ProductionSecurityConfigurationException>()
            .Which.Violations.Should().Contain(v => v.Contains("ScanJobConsumer:Enabled"));
    }

    [Fact]
    public void WorkerValidation_DoesNotRequireWebHostHttpsSetting()
    {
        var settings = CreateValidProductionSettings();
        settings.Remove("Authentication:RequireHttps");

        var act = () => ProductionSecurityConfigurationValidator.Validate(
            BuildConfiguration(settings),
            requireHttps: false);

        act.Should().NotThrow();
    }

    [Fact]
    public void MultipleViolations_AggregatesAllErrors()
    {
        // Missing everything
        var settings = new Dictionary<string, string?>
        {
            ["Authentication:RequireHttps"] = "false",
            ["Database:ConnectionString"] = "",
            ["DataProtection:KeyPath"] = "",
            ["ScannerRuntime:RuntimeMode"] = "UnsafeLocalProcessFallback",
            ["ScannerRuntime:EgressGatewayMode"] = "None"
        };
        var config = BuildConfiguration(settings);

        var act = () => ProductionSecurityConfigurationValidator.Validate(config);

        var ex = act.Should().Throw<ProductionSecurityConfigurationException>().Which;
        ex.Violations.Count.Should().BeGreaterThanOrEqualTo(4);
    }
}
