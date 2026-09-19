using System;
using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IScanWorker
{
    Task<ScanExecutionResult> ExecuteScanJobAsync(Guid scanJobId, CancellationToken ct = default);

    Task<ScanExecutionResult> ExecuteClaimedScanJobAsync(
        Guid scanJobId,
        string expectedWorkerInstanceId,
        int expectedJobVersion,
        CancellationToken ct = default);
}
