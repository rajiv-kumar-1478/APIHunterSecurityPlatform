using System;
using System.Collections.Generic;
using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.Contracts;
using Platform.Infrastructure.Scanning;
using Xunit;

namespace Platform.UnitTests.Scanning;

public class EgressProxyPolicyTests
{
    private readonly EgressPolicyEngine _engine = new(NullLogger<EgressPolicyEngine>.Instance);
    private readonly EgressProxyPolicy _proxyPolicy;

    public EgressProxyPolicyTests()
    {
        _proxyPolicy = new EgressProxyPolicy(_engine, NullLogger<EgressProxyPolicy>.Instance);
    }

    [Fact]
    public void ValidateConnectionRequest_AllowsApprovedIp()
    {
        var approvedIp = IPAddress.Parse("93.184.216.34");
        var target = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { approvedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        var result = _proxyPolicy.ValidateConnectionRequest(target, approvedIp, 443);
        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateConnectionRequest_RejectsUnapprovedIp()
    {
        var approvedIp = IPAddress.Parse("93.184.216.34");
        var unapprovedIp = IPAddress.Parse("8.8.8.8");
        var target = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { approvedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        var result = _proxyPolicy.ValidateConnectionRequest(target, unapprovedIp, 443);
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateConnectionRequest_RejectsExpiredTarget()
    {
        var approvedIp = IPAddress.Parse("93.184.216.34");
        var target = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { approvedIp },
            ResolvedAtUtc: DateTime.UtcNow.AddMinutes(-20),
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(-10),
            PolicyVersion: "v1.0"
        );

        var result = _proxyPolicy.ValidateConnectionRequest(target, approvedIp, 443);
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateRedirectTarget_RejectsPrivateRedirectIp()
    {
        var approvedIp = IPAddress.Parse("93.184.216.34");
        var target = new EgressTarget(
            RawTargetUrl: "https://example.com",
            CanonicalHost: "example.com",
            Port: 443,
            Scheme: "https",
            ApprovedIpAddresses: new HashSet<IPAddress> { approvedIp },
            ResolvedAtUtc: DateTime.UtcNow,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(10),
            PolicyVersion: "v1.0"
        );

        var result = _proxyPolicy.ValidateRedirectTarget(target, "http://169.254.169.254/latest/meta-data/", out var resolvedIp);
        result.Should().BeFalse();
    }
}
