using Microsoft.AspNetCore.Mvc;
using Platform.Application.Permissions;
using Platform.Domain.Contracts;
using Platform.Domain.Enums;

namespace Platform.Api.Controllers;

[ApiController]
public class PermissionsController(PermissionService permissionService, ICurrentUserContext currentUser) : ControllerBase
{
    /// <summary>
    /// Returns ONLY the caller's own permissions for UI rendering.
    /// Non-admins cannot discover the full permission catalog.
    /// </summary>
    [HttpGet("api/v1/permissions")]
    [RequireAuth]
    public async Task<IActionResult> GetMyPermissions(CancellationToken ct)
    {
        if (currentUser.UserId is null) return Unauthorized();

        // Admins get everything
        if (currentUser.IsPlatformAdmin)
            return Ok(await permissionService.GetAllPermissionsAsync(ct));

        return Ok(await permissionService.GetCallerPermissionsAsync(currentUser.UserId.Value, ct));
    }

    /// <summary>Admin: Full permission catalog.</summary>
    [HttpGet("api/v1/admin/permissions")]
    [RequireAdmin]
    public async Task<IActionResult> GetAllPermissions(CancellationToken ct)
        => Ok(await permissionService.GetAllPermissionsAsync(ct));

    /// <summary>Admin: Get permissions for a user.</summary>
    [HttpGet("api/v1/admin/users/{userId:guid}/permissions")]
    [RequireAdmin]
    public async Task<IActionResult> GetUserPermissions(Guid userId, CancellationToken ct)
        => Ok(await permissionService.GetUserPermissionsAsync(userId, ct));

    /// <summary>Admin: Set all permissions for a user.</summary>
    [HttpPut("api/v1/admin/users/{userId:guid}/permissions")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetUserPermissions(Guid userId, [FromBody] SetPermissionsRequest request, CancellationToken ct)
    {
        var result = await permissionService.SetUserPermissionsAsync(new GrantPermissionsCommand(userId, request.PermissionCodes), ct);
        if (!result.IsSuccess) return BadRequest(new { title = result.ErrorMessage });
        return NoContent();
    }

    /// <summary>Admin: Get field permission rules.</summary>
    [HttpGet("api/v1/admin/field-permissions")]
    [RequireAdmin]
    public async Task<IActionResult> GetFieldPermissions(CancellationToken ct)
        => Ok(await permissionService.GetFieldPermissionsAsync(ct));

    /// <summary>Admin: Upsert a field permission rule.</summary>
    [HttpPut("api/v1/admin/field-permissions")]
    [RequireAdmin]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpsertFieldPermission([FromBody] UpsertFieldPermissionRequest request, CancellationToken ct)
    {
        if (!Enum.TryParse<FieldAction>(request.Action, true, out var action))
            return BadRequest(new { title = "Invalid action. Use Read or Write." });

        if (!Enum.TryParse<PermissionEffect>(request.Effect, true, out var effect))
            return BadRequest(new { title = "Invalid effect. Use Allow or Deny." });

        var result = await permissionService.UpsertFieldPermissionAsync(
            new UpsertFieldPermissionCommand(request.PermissionCode, request.ResourceType, request.FieldName, action, effect), ct);

        if (!result.IsSuccess) return BadRequest(new { title = result.ErrorMessage });
        return NoContent();
    }
}

public record SetPermissionsRequest(List<string> PermissionCodes);
public record UpsertFieldPermissionRequest(string PermissionCode, string ResourceType, string FieldName, string Action, string Effect);
