using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Services;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/ai")]
[Authorize]
public class AiProviderController : ControllerBase
{
    private readonly AiProviderRegistryService _registryService;

    public AiProviderController(AiProviderRegistryService registryService)
    {
        _registryService = registryService ?? throw new ArgumentNullException(nameof(registryService));
    }

    [HttpGet("providers")]
    public async Task<ActionResult<List<AiProviderDto>>> GetProviders(CancellationToken ct)
    {
        var providers = await _registryService.GetProvidersAsync(ct);
        return Ok(providers);
    }

    [HttpGet("providers/{id:guid}")]
    public async Task<ActionResult<AiProviderDto>> GetProviderById(Guid id, CancellationToken ct)
    {
        try
        {
            var provider = await _registryService.GetProviderByIdAsync(id, ct);
            return Ok(provider);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpPost("providers")]
    public async Task<ActionResult<AiProviderDto>> CreateProvider([FromBody] CreateAiProviderDto dto, CancellationToken ct)
    {
        var created = await _registryService.CreateProviderConfigAsync(dto, ct);
        return CreatedAtAction(nameof(GetProviderById), new { id = created.Id }, created);
    }

    [HttpPut("providers/{id:guid}")]
    public async Task<ActionResult<AiProviderDto>> UpdateProvider(Guid id, [FromBody] UpdateAiProviderDto dto, CancellationToken ct)
    {
        try
        {
            var updated = await _registryService.UpdateProviderConfigAsync(id, dto, ct);
            return Ok(updated);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpPut("providers/{id:guid}/toggle")]
    public async Task<ActionResult<AiProviderDto>> ToggleProvider(Guid id, [FromBody] ToggleProviderRequest request, CancellationToken ct)
    {
        try
        {
            var toggled = await _registryService.ToggleProviderAsync(id, request.IsEnabled, ct);
            return Ok(toggled);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpPost("providers/{id:guid}/reset-cooldown")]
    public async Task<ActionResult<AiProviderDto>> ResetCooldown(Guid id, CancellationToken ct)
    {
        try
        {
            var reset = await _registryService.ResetProviderCooldownAsync(id, ct);
            return Ok(reset);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpPost("providers/{id:guid}/test")]
    public async Task<ActionResult<AiTestResultDto>> TestProvider(Guid id, CancellationToken ct)
    {
        try
        {
            var testResult = await _registryService.TestProviderConnectionAsync(id, ct);
            return Ok(testResult);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpGet("global-state")]
    public async Task<ActionResult<GlobalAiStateDto>> GetGlobalState(CancellationToken ct)
    {
        var state = await _registryService.GetGlobalAiStateAsync(ct);
        return Ok(state);
    }

    [HttpPut("global-state")]
    public async Task<ActionResult<GlobalAiStateDto>> SetGlobalState([FromBody] ToggleProviderRequest request, CancellationToken ct)
    {
        var updatedState = await _registryService.SetGlobalAiStateAsync(request.IsEnabled, ct);
        return Ok(updatedState);
    }
}

public record ToggleProviderRequest(bool IsEnabled);
