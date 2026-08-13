using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IEgressPolicyEngine
{
    Task<EgressTarget> EvaluateAndBuildTargetAsync(string targetUrl, TimeSpan? ttl = null, CancellationToken ct = default);

    bool IsProhibitedAddress(IPAddress address);

    void ValidateAddress(IPAddress address);
}
