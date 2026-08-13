using System;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class EgressPolicyEngineTests
{
    private readonly EgressPolicyEngine _engine = new(NullLogger<EgressPolicyEngine>.Instance);

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("192.168.255.254")]
    [InlineData("169.254.169.254")] // Cloud IMDS IPv4
    [InlineData("169.254.1.1")]
    [InlineData("100.64.0.1")] // CGNAT
    [InlineData("100.127.255.254")]
    [InlineData("224.0.0.1")] // Multicast
    [InlineData("240.0.0.1")] // Reserved
    [InlineData("0.0.0.0")]
    public void IsProhibitedAddress_IdentifiesProhibitedAddresses(string ipString)
    {
        var ip = IPAddress.Parse(ipString);
        _engine.IsProhibitedAddress(ip).Should().BeTrue($"IP '{ipString}' must be prohibited");
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("93.184.216.34")]
    [InlineData("2606:4700:4700::1111")]
    public void IsProhibitedAddress_AllowsPublicAddresses(string ipString)
    {
        var ip = IPAddress.Parse(ipString);
        _engine.IsProhibitedAddress(ip).Should().BeFalse($"Public IP '{ipString}' should be allowed");
    }

    [Fact]
    public async Task EvaluateAndBuildTargetAsync_RejectsProhibitedLiteralIp()
    {
        Func<Task> act = async () => await _engine.EvaluateAndBuildTargetAsync("https://127.0.0.1");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*prohibited*");
    }

    [Fact]
    public async Task EvaluateAndBuildTargetAsync_RejectsProhibitedCloudImdsLiteralIp()
    {
        Func<Task> act = async () => await _engine.EvaluateAndBuildTargetAsync("http://169.254.169.254/latest/meta-data/");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*prohibited*");
    }

    [Fact]
    public async Task EvaluateAndBuildTargetAsync_RejectsMixedPublicAndPrivateAddresses()
    {
        // Custom mock DNS resolver returning mixed IPv4/IPv6 addresses (1.2.3.4 public, 10.0.0.1 private)
        var customEngine = new EgressPolicyEngine(NullLogger<EgressPolicyEngine>.Instance, host =>
            Task.FromResult(new[] { IPAddress.Parse("1.2.3.4"), IPAddress.Parse("10.0.0.1") }));

        Func<Task> act = async () => await customEngine.EvaluateAndBuildTargetAsync("https://example.com");

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*prohibited*");
    }

    [Fact]
    public async Task EvaluateAndBuildTargetAsync_SucceedsForValidPublicHost()
    {
        var customEngine = new EgressPolicyEngine(NullLogger<EgressPolicyEngine>.Instance, host =>
            Task.FromResult(new[] { IPAddress.Parse("93.184.216.34") }));

        var target = await customEngine.EvaluateAndBuildTargetAsync("https://example.com", TimeSpan.FromMinutes(5));

        target.CanonicalHost.Should().Be("example.com");
        target.ApprovedIpAddresses.Should().Contain(IPAddress.Parse("93.184.216.34"));
        target.IsExpired().Should().BeFalse();
    }

    [Fact]
    public async Task EgressTarget_ExpiresCorrectly()
    {
        var customEngine = new EgressPolicyEngine(NullLogger<EgressPolicyEngine>.Instance, host =>
            Task.FromResult(new[] { IPAddress.Parse("93.184.216.34") }));

        var target = await customEngine.EvaluateAndBuildTargetAsync("https://example.com", TimeSpan.FromSeconds(-1));

        target.IsExpired().Should().BeTrue();
    }
}
