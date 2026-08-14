using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Adapters;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;
using Platform.Application.Scanning.Validation;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Adapters;

public class SemgrepAdapterTests
{
    private readonly SemgrepAdapter _adapter;
    private readonly SemgrepOutputParser _parser;

    public SemgrepAdapterTests()
    {
        _parser = new SemgrepOutputParser(NullLogger<SemgrepOutputParser>.Instance);
        _adapter = new SemgrepAdapter(_parser);
    }

    [Fact]
    public void Manifest_IsValidAccordingToContract()
    {
        var result = ScanToolManifestValidator.Validate(_adapter.Manifest);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal("semgrep", _adapter.Manifest.ToolKey);
        Assert.Equal("1.172.0", _adapter.Manifest.Version);
        Assert.StartsWith("sha256:", _adapter.Manifest.ContainerImageDigest);
        Assert.Contains(SecurityScanProfileType.Standard, _adapter.Manifest.SupportedProfiles);
        Assert.Contains(SecurityScanProfileType.Deep, _adapter.Manifest.SupportedProfiles);
        Assert.Contains("sast.scan", _adapter.Manifest.Capabilities);
    }

    [Fact]
    public void PrepareExecution_StandardProfile_BuildsDeterministicRuleArguments()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Equal("semgrep", plan.ToolKey);
        Assert.Contains("scan", plan.CommandLineArguments);
        Assert.Contains("--json", plan.CommandLineArguments);
        Assert.Contains("p/r2c-security-audit", plan.CommandLineArguments);
        Assert.Contains("p/owasp-top-ten", plan.CommandLineArguments);
        Assert.DoesNotContain("p/csharp", plan.CommandLineArguments);
    }

    [Fact]
    public void PrepareExecution_DeepProfile_IncludesDeepRulePacks()
    {
        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Deep,
            TenantId: Guid.NewGuid()
        );

        var plan = _adapter.PrepareExecution(context);

        Assert.Contains("p/csharp", plan.CommandLineArguments);
        Assert.Contains("p/golang", plan.CommandLineArguments);
        Assert.Contains("p/sql-injection", plan.CommandLineArguments);
    }

    [Fact]
    public async Task ParseOutput_ValidGoldenSemgrepJson_ExtractsSqlInjectionAndSsrfFindings()
    {
        var json = @"{
  ""results"": [
    {
      ""check_id"": ""csharp.dotnet.security.audit.sqli.sql-injection-command"",
      ""path"": ""src/Services/UserService.cs"",
      ""start"": { ""line"": 42, ""col"": 12 },
      ""end"": { ""line"": 42, ""col"": 55 },
      ""extra"": {
        ""message"": ""Potential SQL injection in SqlCommand constructor."",
        ""metadata"": {
          ""cwe"": [ ""CWE-89: Improper Neutralization of Special Elements in SQL"" ],
          ""owasp"": [ ""A03:2021 - Injection"" ]
        },
        ""severity"": ""ERROR"",
        ""lines"": ""var cmd = new SqlCommand(\""SELECT * FROM Users WHERE id = '\"" + userId + \""'\"", conn);""
      }
    },
    {
      ""check_id"": ""csharp.dotnet.security.audit.ssrf.httpclient-taint"",
      ""path"": ""src/Controllers/ProxyController.cs"",
      ""start"": { ""line"": 18, ""col"": 5 },
      ""end"": { ""line"": 18, ""col"": 45 },
      ""extra"": {
        ""message"": ""Potential Server-Side Request Forgery via user-supplied URL."",
        ""metadata"": {
          ""cwe"": [ ""CWE-918: Server-Side Request Forgery"" ]
        },
        ""severity"": ""WARNING"",
        ""lines"": ""await client.GetAsync(userProvidedUrl);""
      }
    }
  ],
  ""paths"": {
    ""scanned"": [ ""src/Services/UserService.cs"", ""src/Controllers/ProxyController.cs"", ""src/Program.cs"" ]
  },
  ""errors"": []
}";

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("semgrep", "1.172.0", 0, json, string.Empty, Encoding.UTF8.GetByteCount(json), 450);
        var result = await _adapter.ParseOutputAsync(context, raw);

        Assert.Equal(2, result.FindingCandidates.Count);

        var sqli = result.FindingCandidates.First(c => c.RuleOrTemplateId == "csharp.dotnet.security.audit.sqli.sql-injection-command");
        Assert.Equal("high", sqli.RawSeverity);
        Assert.Equal("CWE-89", sqli.CweId);
        Assert.Equal("src/Services/UserService.cs", sqli.EndpointPath);
        Assert.Equal("Line:42", sqli.ParameterName);
        Assert.Equal(FindingType.ProductionServiceExposed, sqli.FindingType);

        var ssrf = result.FindingCandidates.First(c => c.RuleOrTemplateId == "csharp.dotnet.security.audit.ssrf.httpclient-taint");
        Assert.Equal("medium", ssrf.RawSeverity);
        Assert.Equal("CWE-918", ssrf.CweId);
        Assert.Equal("src/Controllers/ProxyController.cs", ssrf.EndpointPath);

        Assert.Equal(3, result.Coverage.EndpointsDiscovered); // Scanned files
    }

    [Fact]
    public async Task ParseOutput_ExcessiveOutputBytes_EnforcesMaxOutputLimits()
    {
        var hugeOutput = new string('A', SemgrepOutputParser.MaxRawOutputBytes + 100);

        var context = new ScanExecutionContext(
            ScanJobId: Guid.NewGuid(),
            TargetUrl: "https://github.com/org/repo",
            Profile: SecurityScanProfileType.Standard,
            TenantId: Guid.NewGuid()
        );

        var raw = new ToolExecutionRawOutput("semgrep", "1.172.0", 0, hugeOutput, string.Empty, Encoding.UTF8.GetByteCount(hugeOutput), 100);
        var result = await _adapter.ParseOutputAsync(context, raw);

        Assert.Empty(result.FindingCandidates);
        Assert.True(result.Coverage.CoverageTruncated);
        Assert.Equal("MaxRawOutputBytesExceeded", result.Coverage.CoverageTruncationReason);
    }
}
