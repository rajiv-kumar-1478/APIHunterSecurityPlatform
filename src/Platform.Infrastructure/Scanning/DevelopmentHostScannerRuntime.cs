using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Development and test harness implementation of IScannerRuntimeSandbox.
/// Directly dispatches to IGenericCliToolAdapter on the host machine.
/// STRICT GUARD: Throws InvalidOperationException if instantiated in a Production environment.
/// </summary>
public sealed class DevelopmentHostScannerRuntime : IScannerRuntimeSandbox
{
    private readonly Func<string, IGenericCliToolAdapter> _cliAdapterFactory;
    private readonly IEnforcedEgressGateway _egressGateway;
    private readonly ScannerRuntimeOptions _options;
    private readonly ILogger<DevelopmentHostScannerRuntime> _logger;

    public DevelopmentHostScannerRuntime(
        Func<string, IGenericCliToolAdapter> cliAdapterFactory,
        IEnforcedEgressGateway egressGateway,
        ScannerRuntimeOptions? options = null,
        ILogger<DevelopmentHostScannerRuntime>? logger = null,
        bool isProductionEnvironment = false)
    {
        var aspnetEnv = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var isProd = isProductionEnvironment || string.Equals(aspnetEnv, "Production", StringComparison.OrdinalIgnoreCase);

        if (isProd)
        {
            throw new InvalidOperationException("CRITICAL_SECURITY_VIOLATION: DevelopmentHostScannerRuntime cannot be initialized in a Production environment.");
        }

        _cliAdapterFactory = cliAdapterFactory ?? throw new ArgumentNullException(nameof(cliAdapterFactory));
        _egressGateway = egressGateway ?? throw new ArgumentNullException(nameof(egressGateway));
        _options = options ?? new ScannerRuntimeOptions();
        _logger = logger ?? NullLogger<DevelopmentHostScannerRuntime>.Instance;
    }

    public async Task<ToolExecutionResult> ExecuteInSandboxAsync(
        ToolExecutionRequest request,
        EgressTarget egressTarget,
        ProviderSecretLease secretLease,
        string scratchDirectory,
        CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        if (egressTarget == null) throw new ArgumentNullException(nameof(egressTarget));
        if (secretLease == null) throw new ArgumentNullException(nameof(secretLease));

        if (egressTarget.IsExpired(DateTime.UtcNow))
        {
            _logger.LogError("DevelopmentHostScannerRuntime rejected execution: Egress target for host '{Host}' has expired.", egressTarget.CanonicalHost);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "EXPIRED_EGRESS_AUTHORIZATION");
        }

        // Establish scoped egress session
        await using var gatewaySession = await _egressGateway.CreateScopedSessionAsync(egressTarget, cancellationToken);

        _logger.LogWarning("DEVELOPMENT_MODE_HOST_EXECUTION: Running direct host process for tool '{ToolKey}' (Dev/Test Harness Only).", request.ToolKey);

        var adapter = _cliAdapterFactory(request.ToolKey);
        return await adapter.ExecuteAsync(request, secretLease, scratchDirectory, cancellationToken);
    }
}
