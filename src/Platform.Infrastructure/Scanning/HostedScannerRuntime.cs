using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

/// <summary>
/// Hosted Scanner Runtime Sandbox for Render Private Services / Railway Internal Mesh.
/// Communicates with dedicated scanner services over internal private networks using X-Scanner-Service-Key authentication.
/// Deserializes actual ToolExecutionResult receipts returned by remote scanner endpoints.
/// Fails closed with HOSTED_INVALID_EXECUTION_RECEIPT on empty, malformed, or missing receipt payloads.
/// </summary>
public class HostedScannerRuntime : IScannerRuntimeSandbox
{
    private const string ServiceKeyHeader = "X-Scanner-Service-Key";
    private readonly HttpClient _httpClient;
    private readonly string? _serviceKey;
    private readonly IEnforcedEgressGateway _egressGateway;
    private readonly ILogger<HostedScannerRuntime> _logger;

    public HostedScannerRuntime(
        HttpClient httpClient,
        string? serviceKey,
        IEnforcedEgressGateway egressGateway,
        ILogger<HostedScannerRuntime> logger)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _serviceKey = serviceKey;
        _egressGateway = egressGateway ?? throw new ArgumentNullException(nameof(egressGateway));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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

        // 1. Fail Closed on Missing Service Authentication Key
        if (string.IsNullOrWhiteSpace(_serviceKey))
        {
            _logger.LogError("HostedScannerRuntime execution rejected: Missing or unconfigured X-Scanner-Service-Key secret.");
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "MISSING_SERVICE_AUTHENTICATION_KEY");
        }

        // 2. Fail Closed on Missing Endpoint
        if (_httpClient.BaseAddress == null)
        {
            _logger.LogError("HostedScannerRuntime execution rejected: HostedScannerServiceEndpoint is not configured.");
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "HOSTED_ENDPOINT_NOT_CONFIGURED");
        }

        // 3. Fail Closed on Expired Egress Target Authorization
        if (egressTarget.IsExpired(DateTime.UtcNow))
        {
            _logger.LogError("HostedScannerRuntime execution rejected: EgressTarget for host '{Host}' has expired.", egressTarget.CanonicalHost);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "EXPIRED_EGRESS_AUTHORIZATION");
        }

        // 4. Establish Scoped Enforced Egress Gateway Session
        await using var scopedPolicy = await _egressGateway.CreateScopedSessionAsync(egressTarget, cancellationToken);

        // 5. Remote Private Service Endpoint Dispatch
        try
        {
            _logger.LogInformation("HostedScannerRuntime dispatching execution request for tool '{ToolKey}' to private service endpoint '{BaseAddress}'.",
                request.ToolKey, _httpClient.BaseAddress);

            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/scanner/execute");
            httpRequest.Headers.Add(ServiceKeyHeader, _serviceKey);

            var payload = JsonSerializer.Serialize(new
            {
                JobId = request.ScanJobId,
                ToolKey = request.ToolKey,
                Version = request.Version,
                Executable = request.Executable,
                ContainerImageRepository = request.ContainerImageRepository,
                ContainerImageDigest = request.ContainerImageDigest,
                TargetUrl = egressTarget.RawTargetUrl,
                CanonicalHost = egressTarget.CanonicalHost,
                TimeoutSeconds = request.Timeout.TotalSeconds
            });

            httpRequest.Content = new StringContent(payload, Encoding.UTF8, "application/json");

            using var response = await _httpClient.SendAsync(httpRequest, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Hosted scanner service returned non-success HTTP status code {StatusCode}.", response.StatusCode);
                return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, (int)response.StatusCode, null, "HOSTED_SERVICE_HTTP_ERROR");
            }

            var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(responseJson))
            {
                _logger.LogError("Hosted scanner service returned empty response payload.");
                return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "HOSTED_INVALID_EXECUTION_RECEIPT");
            }

            try
            {
                var remoteResult = JsonSerializer.Deserialize<ToolExecutionResult>(responseJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (remoteResult != null && !string.IsNullOrWhiteSpace(remoteResult.ToolKey))
                {
                    _logger.LogInformation("HostedScannerRuntime received remote execution receipt for tool '{ToolKey}' (Status: {Status}, ExitCode: {Code}).",
                        remoteResult.ToolKey, remoteResult.Status, remoteResult.ExitCode);
                    return remoteResult;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to deserialize remote scanner service response receipt.");
                return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "HOSTED_INVALID_EXECUTION_RECEIPT");
            }

            _logger.LogError("Hosted scanner service response payload lacked required execution receipt fields.");
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, "HOSTED_INVALID_EXECUTION_RECEIPT");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute scan tool '{ToolKey}' on private hosted scanner service.", request.ToolKey);
            return new ToolExecutionResult(request.ToolKey, request.Version, ToolExecutionStatus.Failed, -1, null, $"HOSTED_SERVICE_UNAVAILABLE: {ex.Message}");
        }
    }
}
