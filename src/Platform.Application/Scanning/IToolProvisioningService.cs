using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;

namespace Platform.Application.Scanning;

public interface IToolProvisioningService
{
    Task<ProvisioningResult> ProvisionToolAsync(SecurityScanTool tool, CancellationToken ct = default);
}
