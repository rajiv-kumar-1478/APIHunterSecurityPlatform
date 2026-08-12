using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Services;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/intelligence")]
[Authorize]
public class SecurityIntelligenceController : ControllerBase
{
    private readonly SecurityIntelligenceService _intelligenceService;

    public SecurityIntelligenceController(SecurityIntelligenceService intelligenceService)
    {
        _intelligenceService = intelligenceService ?? throw new ArgumentNullException(nameof(intelligenceService));
    }

    [HttpGet("graph")]
    public async Task<ActionResult<GraphResponseDto>> GetGraph(
        [FromQuery] Guid? repositoryId,
        [FromQuery] string? nodeType,
        [FromQuery] string? discoverySource,
        CancellationToken ct)
    {
        var graph = await _intelligenceService.GetGraphAsync(repositoryId, nodeType, discoverySource, ct);
        return Ok(graph);
    }

    [HttpGet("nodes")]
    public async Task<ActionResult<PagedResultDto<IntelligenceNodeDto>>> GetNodes(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? nodeType = null,
        CancellationToken ct = default)
    {
        var nodes = await _intelligenceService.GetNodesAsync(page, pageSize, nodeType, ct);
        return Ok(nodes);
    }

    [HttpGet("nodes/{id:guid}")]
    public async Task<ActionResult<IntelligenceNodeDetailsDto>> GetNodeById(Guid id, CancellationToken ct)
    {
        try
        {
            var node = await _intelligenceService.GetNodeByIdAsync(id, ct);
            return Ok(node);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpGet("nodes/{id:guid}/relationships")]
    public async Task<ActionResult<NodeRelationshipsDto>> GetNodeRelationships(Guid id, CancellationToken ct)
    {
        var relationships = await _intelligenceService.GetNodeRelationshipsAsync(id, ct);
        return Ok(relationships);
    }

    [HttpGet("edges")]
    public async Task<ActionResult<PagedResultDto<IntelligenceEdgeDto>>> GetEdges(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? edgeType = null,
        [FromQuery] string? discoverySource = null,
        CancellationToken ct = default)
    {
        var edges = await _intelligenceService.GetEdgesAsync(page, pageSize, edgeType, discoverySource, ct);
        return Ok(edges);
    }

    [HttpPost("graph/rebuild")]
    [Authorize(Policy = "PlatformAdmin")]
    public async Task<IActionResult> RebuildGraph([FromBody] RebuildGraphRequest request, CancellationToken ct)
    {
        try
        {
            await _intelligenceService.RebuildGraphForRepositoryAsync(request.RepositoryId, ct);
            return Ok(new { message = $"Graph rebuild completed successfully for repository '{request.RepositoryId}'." });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }
}
