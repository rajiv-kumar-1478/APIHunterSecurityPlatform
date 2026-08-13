using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IScanProvider
{
    string ProviderKey { get; }

    Task<ScanStartResult> StartAsync(ScanExecutionRequest request, CancellationToken ct = default);

    Task<ScanStatusResult> GetStatusAsync(string externalScanId, CancellationToken ct = default);

    Task<ScanResult> GetResultAsync(string externalScanId, CancellationToken ct = default);

    Task CancelAsync(string externalScanId, CancellationToken ct = default);
}
