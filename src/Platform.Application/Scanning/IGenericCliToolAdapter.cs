using System.Threading;
using System.Threading.Tasks;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning;

public interface IGenericCliToolAdapter
{
    string ToolKey { get; }

    Task<ToolExecutionResult> ExecuteAsync(
        ToolExecutionRequest request,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        CancellationToken ct = default);
}
