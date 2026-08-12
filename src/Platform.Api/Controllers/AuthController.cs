using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Platform.Application.Auth;
using Platform.Application.Users;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AuthController(AuthService authService, IAntiforgery antiforgery) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken ct)
    {
        var command = new LoginCommand(
            request.Email,
            request.Password,
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            Request.Headers["User-Agent"].ToString());

        var result = await authService.LoginAsync(command, ct);
        if (!result.IsSuccess)
            return Unauthorized(new { title = result.ErrorMessage, code = result.ErrorCode });

        var session = result.Value!;

        // Build claims principal
        var claims = new List<Claim>
        {
            new("sub", session.SessionId.ToString()),
            new("sid", session.SessionId.ToString()),
            new("platform_admin", session.IsPlatformAdmin.ToString().ToLower())
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Platform"));

        await HttpContext.SignInAsync("Platform", principal, new AuthenticationProperties
        {
            IsPersistent = request.RememberMe,
            ExpiresUtc = session.ExpiresAtUtc,
            AllowRefresh = true
        });

        // Return CSRF token for the new session
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);

        return Ok(new
        {
            isPlatformAdmin = session.IsPlatformAdmin,
            expiresAt = session.ExpiresAtUtc,
            csrfToken = tokens.RequestToken
        });
    }

    [HttpPost("logout")]
    [RequireAuth]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        var sessionIdClaim = User.FindFirst("sid")?.Value;
        if (Guid.TryParse(sessionIdClaim, out var sessionId))
            await authService.LogoutAsync(sessionId, ct);

        await HttpContext.SignOutAsync("Platform");
        return NoContent();
    }

    [HttpGet("me")]
    [RequireAuth]
    public IActionResult Me()
    {
        return Ok(new
        {
            userId = User.FindFirst("sub")?.Value,
            isPlatformAdmin = User.HasClaim("platform_admin", "true")
        });
    }

    [HttpGet("sessions")]
    [RequireAuth]
    public async Task<IActionResult> GetSessions(CancellationToken ct)
    {
        var userId = GetUserId();
        var currentSessionId = GetSessionId();
        var sessions = await authService.GetUserSessionsAsync(userId, currentSessionId, ct);
        return Ok(sessions);
    }

    [HttpDelete("sessions/{id:guid}")]
    [RequireAuth]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeSession(Guid id, CancellationToken ct)
    {
        var result = await authService.RevokeSessionAsync(id, ct);
        if (!result.IsSuccess) return BadRequest(new { title = result.ErrorMessage });
        return NoContent();
    }

    [HttpGet("csrf")]
    [RequireAuth]
    public IActionResult GetCsrfToken()
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return Ok(new { csrfToken = tokens.RequestToken });
    }

    private Guid GetUserId() => Guid.Parse(User.FindFirst("sub")!.Value);
    private Guid? GetSessionId()
    {
        var sid = User.FindFirst("sid")?.Value;
        return Guid.TryParse(sid, out var id) ? id : null;
    }
}

public record LoginRequest(string Email, string Password, bool RememberMe = false);
