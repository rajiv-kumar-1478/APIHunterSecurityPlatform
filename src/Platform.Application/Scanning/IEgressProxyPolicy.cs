using System.Net;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IEgressProxyPolicy
{
    bool ValidateConnectionRequest(EgressTarget target, IPAddress destinationIp, int port);

    bool ValidateRedirectTarget(EgressTarget target, string redirectUrl, out IPAddress? resolvedIp);
}
