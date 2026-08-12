using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Entities;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/validation")]
public class CredentialValidationController : ControllerBase
{
    private readonly CredentialValidationService _validationService;
    private readonly IPlatformDbContext _dbContext;

    public CredentialValidationController(
        CredentialValidationService validationService,
        IPlatformDbContext dbContext)
    {
        _validationService = validationService ?? throw new ArgumentNullException(nameof(validationService));
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
    }

    [HttpPost("candidates/{candidateId:guid}/validate")]
    public async Task<IActionResult> ValidateCandidate(Guid candidateId, [FromQuery] bool immediate = true, CancellationToken ct = default)
    {
        if (immediate)
        {
            var result = await _validationService.ValidateCandidateAsync(candidateId, null, ct);
            return Ok(result);
        }
        else
        {
            var job = await _validationService.EnqueueValidationJobAsync(candidateId, ct);
            return Accepted(new { jobId = job.Id, status = job.Status.ToString() });
        }
    }

    [HttpGet("candidates/{candidateId:guid}/history")]
    public async Task<IActionResult> GetValidationHistory(Guid candidateId, CancellationToken ct = default)
    {
        var history = await _validationService.GetValidationHistoryAsync(candidateId, ct);
        return Ok(history);
    }

    [HttpGet("results/{resultId:guid}")]
    public async Task<IActionResult> GetValidationResult(Guid resultId, CancellationToken ct = default)
    {
        var result = await _dbContext.CredentialValidationResults
            .Include(r => r.Candidate)
            .FirstOrDefaultAsync(r => r.Id == resultId, ct);

        if (result == null) return NotFound();
        return Ok(result);
    }
}
