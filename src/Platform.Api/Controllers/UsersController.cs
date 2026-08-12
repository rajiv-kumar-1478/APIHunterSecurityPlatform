using Microsoft.AspNetCore.Mvc;
using Platform.Application.Common;
using Platform.Application.Users;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/users")]
[RequireAdmin]
public class UsersController(UserService userService) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 50, CancellationToken ct = default)
    {
        var result = await userService.GetUsersAsync(new PaginationRequest(page, pageSize), ct);
        return Ok(result);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetUser(Guid id, CancellationToken ct)
    {
        var user = await userService.GetUserByIdAsync(id, ct);
        if (user is null) return NotFound(new { title = "User not found" });
        return Ok(user);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request, CancellationToken ct)
    {
        var result = await userService.CreateUserAsync(
            new CreateUserCommand(request.Email, request.Username, request.DisplayName, request.Password, request.IsPlatformAdmin), ct);

        if (!result.IsSuccess)
            return BadRequest(new { title = result.ErrorMessage, code = result.ErrorCode });

        return CreatedAtAction(nameof(GetUser), new { id = result.Value!.Id }, result.Value);
    }

    [HttpPatch("{id:guid}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserRequest request, CancellationToken ct)
    {
        var result = await userService.UpdateUserAsync(
            new UpdateUserCommand(id, request.DisplayName, request.IsActive, request.IsPlatformAdmin), ct);

        if (!result.IsSuccess)
            return BadRequest(new { title = result.ErrorMessage, code = result.ErrorCode });

        return Ok(result.Value);
    }
}

public record CreateUserRequest(string Email, string Username, string DisplayName, string Password, bool IsPlatformAdmin = false);
public record UpdateUserRequest(string? DisplayName, bool? IsActive, bool? IsPlatformAdmin);
