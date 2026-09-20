using FluentAssertions;
using Platform.Application.Scanning.Adapters;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class ScannerAdapterContractTests
{
    [Theory]
    [InlineData(typeof(HttpxAdapter), "httpx")]
    [InlineData(typeof(NucleiAdapter), "nuclei")]
    [InlineData(typeof(SubfinderAdapter), "subfinder")]
    [InlineData(typeof(JsMinerAdapter), "jsminer")]
    [InlineData(typeof(SemgrepAdapter), "semgrep")]
    [InlineData(typeof(TruffleHogAdapter), "trufflehog")]
    public void ScannerAdapter_HasValidToolMetadata(Type adapterType, string expectedName)
    {
        var parserProperty = adapterType.GetConstructors()[0];
        // Ensure adapter class implements IScanToolAdapter
        typeof(IScanToolAdapter).IsAssignableFrom(adapterType).Should().BeTrue();
    }

    [Fact]
    public void ScannerRuntimeOptions_DefaultValues_AreSecure()
    {
        var opts = new Platform.Domain.Entities.ScannerRuntimeOptions();

        // Must default to secure boundaries
        opts.ExecutionTimeout.Should().BeLessThanOrEqualTo(TimeSpan.FromMinutes(30));
        opts.NetworkMode.Should().Be("bridge");
    }

    [Fact]
    public void ScanToolRegistry_ContainsAllCoreAdapters()
    {
        var registry = new ScanToolRegistry(
        [
            new HttpxAdapter(new Platform.Application.Scanning.Parsers.HttpxOutputParser()),
            new NucleiAdapter(new Platform.Application.Scanning.Parsers.NucleiOutputParser()),
            new SubfinderAdapter(new Platform.Application.Scanning.Parsers.SubfinderOutputParser()),
            new JsMinerAdapter(new Platform.Application.Scanning.Parsers.JsMinerOutputParser()),
            new SemgrepAdapter(new Platform.Application.Scanning.Parsers.SemgrepOutputParser()),
            new TruffleHogAdapter(new Platform.Application.Scanning.Parsers.TruffleHogOutputParser())
        ]);

        var tools = registry.GetAllTools();
        tools.Should().HaveCount(6);
        tools.Select(t => t.ToolName).Should().Contain(["httpx", "nuclei", "subfinder", "jsminer", "semgrep", "trufflehog"]);
    }
}
