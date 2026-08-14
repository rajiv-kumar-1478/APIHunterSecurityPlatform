using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IScanToolHealthService
{
    Task<ScanToolDto> CheckToolHealthAsync(string toolKey, CancellationToken ct = default);

    Task<IReadOnlyList<ScanToolDto>> GetAllToolStatusAsync(CancellationToken ct = default);

    Task<ScannerRuntimeHealthDto> GetScannerRuntimeHealthAsync(CancellationToken ct = default);
}
