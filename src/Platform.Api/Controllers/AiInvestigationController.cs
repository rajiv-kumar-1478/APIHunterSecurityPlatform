using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Services;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/ai/investigations")]
[Authorize]
public class AiInvestigationController : ControllerBase
{
    private readonly AiInvestigationService _investigationService;

    public AiInvestigationController(AiInvestigationService investigationService)
    {
        _investigationService = investigationService ?? throw new ArgumentNullException(nameof(investigationService));
    }

    [HttpPost]
    public async Task<ActionResult<AiInvestigationJobDto>> TriggerInvestigation([FromBody] TriggerInvestigationRequest request, CancellationToken ct)
    {
        try
        {
            var job = await _investigationService.TriggerInvestigationAsync(request.RepositoryId, request.SnapshotId, ct);
            return CreatedAtAction(nameof(GetInvestigationById), new { id = job.Id }, job);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpGet]
    public async Task<ActionResult<List<AiInvestigationJobDto>>> GetInvestigations(CancellationToken ct)
    {
        var jobs = await _investigationService.GetInvestigationsAsync(ct);
        return Ok(jobs);
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<AiInvestigationJobDetailsDto>> GetInvestigationById(Guid id, CancellationToken ct)
    {
        try
        {
            var details = await _investigationService.GetInvestigationByIdAsync(id, ct);
            return Ok(details);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpPost("{id:guid}/pause")]
    public async Task<ActionResult<AiInvestigationJobDto>> PauseInvestigation(Guid id, CancellationToken ct)
    {
        try
        {
            var paused = await _investigationService.PauseInvestigationAsync(id, ct);
            return Ok(paused);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpPost("{id:guid}/resume")]
    public async Task<ActionResult<AiInvestigationJobDto>> ResumeInvestigation(Guid id, CancellationToken ct)
    {
        try
        {
            var resumed = await _investigationService.ResumeInvestigationAsync(id, ct);
            return Ok(resumed);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpPost("{id:guid}/cancel")]
    public async Task<ActionResult<AiInvestigationJobDto>> CancelInvestigation(Guid id, CancellationToken ct)
    {
        try
        {
            var cancelled = await _investigationService.CancelInvestigationAsync(id, ct);
            return Ok(cancelled);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }
}
