using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Permissions;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/detection-rules")]
public class DetectionRuleController(
    IPlatformDbContext dbContext,
    ICurrentUserContext currentUser,
    PermissionService permissionService) : ControllerBase
{
    public record CreateRuleRequest(string Id, int Version, string Description, string RegexPattern, string CredentialType, string Confidence);

    [HttpGet]
    public async Task<IActionResult> GetRules(CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "rule.view", ct);
            if (!hasPermission) return Forbid();
        }

        var rules = await dbContext.DetectionRules
            .OrderBy(r => r.CredentialType)
            .ThenBy(r => r.Id)
            .Select(r => new
            {
                r.Id,
                r.Version,
                r.Description,
                r.RegexPattern,
                r.CredentialType,
                r.Confidence,
                r.IsEnabled,
                RuleSource = r.Source.ToString(),
                r.CreatedAtUtc
            })
            .ToListAsync(ct);

        return Ok(rules);
    }

    [HttpPost]
    public async Task<IActionResult> CreateRule([FromBody] CreateRuleRequest request, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "rule.manage", ct);
            if (!hasPermission) return Forbid();
        }

        if (await dbContext.DetectionRules.AnyAsync(r => r.Id == request.Id && r.Version == request.Version, ct))
        {
            return Conflict(new { Message = $"Rule '{request.Id}' v{request.Version} already exists." });
        }

        var rule = new DetectionRule
        {
            Id = request.Id,
            Version = request.Version,
            Description = request.Description,
            RegexPattern = request.RegexPattern,
            CredentialType = request.CredentialType,
            Confidence = request.Confidence,
            IsEnabled = true,
            Source = RuleSource.Custom
        };


        dbContext.DetectionRules.Add(rule);
        await dbContext.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(GetRules), new { id = rule.Id, version = rule.Version }, rule);
    }

    [HttpPost("{id}/{version:int}/toggle")]
    public async Task<IActionResult> ToggleRule(string id, int version, [FromQuery] bool enabled, CancellationToken ct = default)
    {
        if (!currentUser.IsPlatformAdmin)
        {
            var hasPermission = currentUser.UserId.HasValue && await permissionService.HasPermissionAsync(currentUser.UserId.Value, "rule.manage", ct);
            if (!hasPermission) return Forbid();
        }

        var rule = await dbContext.DetectionRules.FirstOrDefaultAsync(r => r.Id == id && r.Version == version, ct);
        if (rule == null) return NotFound(new { Message = $"Rule '{id}' v{version} not found." });

        rule.IsEnabled = enabled;
        await dbContext.SaveChangesAsync(ct);

        return Ok(new { Message = $"Rule '{id}' v{version} enabled state set to {enabled}." });
    }
}
