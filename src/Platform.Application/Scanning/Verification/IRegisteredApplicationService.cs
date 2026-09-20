using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Platform.Application.Scanning.Verification;

public sealed record RegisteredApplicationDto(
    Guid Id,
    string ApplicationId,
    string DisplayName,
    string AuthorizedTargetUrl,
    string Environment,
    bool Enabled,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public sealed record RegisterApplicationRequest(
    string ApplicationId,
    string DisplayName,
    string AuthorizedTargetUrl,
    string Environment);

public sealed record RegistrationResultDto(
    RegisteredApplicationDto Application,
    string RawSigningSecret);

public sealed record SecretRotationResultDto(
    Guid Id,
    string ApplicationId,
    string RawSigningSecret);

public interface IRegisteredApplicationService
{
    Task<IReadOnlyList<RegisteredApplicationDto>> GetApplicationsAsync(Guid tenantId, CancellationToken ct = default);
    Task<RegisteredApplicationDto?> GetByIdAsync(Guid tenantId, Guid id, CancellationToken ct = default);
    Task<RegistrationResultDto> RegisterApplicationAsync(Guid tenantId, RegisterApplicationRequest req, CancellationToken ct = default);
    Task<SecretRotationResultDto> RegenerateSecretAsync(Guid tenantId, Guid id, CancellationToken ct = default);
    Task<RegisteredApplicationDto> ToggleStatusAsync(Guid tenantId, Guid id, bool enabled, CancellationToken ct = default);
    Task<bool> DeleteApplicationAsync(Guid tenantId, Guid id, CancellationToken ct = default);
}
