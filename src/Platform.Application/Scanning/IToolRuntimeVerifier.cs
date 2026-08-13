using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;

namespace Platform.Application.Scanning;

public interface IToolRuntimeVerifier
{
    Task<ToolProbeResult> ProbeToolAsync(SecurityScanTool tool, CancellationToken ct = default);
}
