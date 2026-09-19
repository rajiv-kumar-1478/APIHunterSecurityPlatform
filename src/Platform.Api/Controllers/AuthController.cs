using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Platform.Application.Auth;

namespace Platform.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AuthController(AuthService authService, IAntiforgery antiforgery) : ControllerBase
{
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken ct)
    {
        var command = new LoginCommand(
            request.Email,
            request.Password,
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            Request.Headers.UserAgent.ToString());

        var result = await authService.LoginAsync(command, ct);
        if (!result.IsSuccess || result.Value is null)
        {
            return Unauthorized(new
            {
                title = result.ErrorMessage ?? "Authentication failed.",
                code = result.ErrorCode ?? "AUTH_FAILED"
            });
        }

        var session = result.Value;
        var claims = new List<Claim>
        {
            new("sub", session.UserId.ToString()),
            new("sid", session.SessionId.ToString()),
            new("platform_admin", session.IsPlatformAdmin.ToString().ToLowerInvariant())
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Platform"));

        await HttpContext.SignInAsync("Platform", principal, new AuthenticationProperties
        {
            IsPersistent = request.RememberMe,
            ExpiresUtc = session.ExpiresAtUtc,
            AllowRefresh = false
        });

        // Ensure the response token is bound to the newly authenticated identity.
        HttpContext.User = principal;
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);

        return Ok(new
        {
            userId = session.UserId,
            isPlatformAdmin = session.IsPlatformAdmin,
            expiresAt = session.ExpiresAtUtc,
            csrfToken = tokens.RequestToken
        });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        var sessionIdClaim = User.FindFirst("sid")?.Value;
        if (Guid.TryParse(sessionIdClaim, out var sessionId))
        {
            await authService.LogoutAsync(sessionId, ct);
        }

        await HttpContext.SignOutAsync("Platform");
        return NoContent();
    }

    [HttpGet("me")]
    public IActionResult Me()
    {
        return Ok(new
        {
            userId = User.FindFirst("sub")?.Value,
            isPlatformAdmin = User.HasClaim("platform_admin", "true")
        });
    }

    [HttpGet("sessions")]
    public async Task<IActionResult> GetSessions(CancellationToken ct)
    {
        var sessions = await authService.GetUserSessionsAsync(GetUserId(), GetSessionId(), ct);
        return Ok(sessions);
    }

    [HttpDelete("sessions/{id:guid}")]
    public async Task<IActionResult> RevokeSession(Guid id, CancellationToken ct)
    {
        var result = await authService.RevokeSessionAsync(id, ct);
        if (result.IsSuccess)
        {
            return NoContent();
        }

        return result.ErrorCode switch
        {
            "ACCESS_DENIED" => Forbid(),
            "NOT_FOUND" => NotFound(new { title = result.ErrorMessage, code = result.ErrorCode }),
            _ => BadRequest(new { title = result.ErrorMessage, code = result.ErrorCode })
        };
    }

    [AllowAnonymous]
    [HttpGet("csrf")]
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
