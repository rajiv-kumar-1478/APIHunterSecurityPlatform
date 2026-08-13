using System.Threading;
using System.Threading.Tasks;

namespace Platform.Application.Scanning;

public interface IToolDependencyValidator
{
    Task ValidateDependencyGraphAsync(string rootToolKey, CancellationToken ct = default);
}
