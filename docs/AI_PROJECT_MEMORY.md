# APIHunter Security Intelligence Platform
# AI PROJECT MEMORY
# Last Updated: 2026-08-12

---

## Project

APIHunter Security Intelligence Platform

## Repository

```
C:\Users\rk170\Desktop\APIHunterSecurityPlatform\
```

## External Repository (READ ONLY — DO NOT MODIFY)

```
C:\Users\rk170\Desktop\unsecureAPI project\APIHunterV2\
```

APIHunterV2 is NOT modified during Phase 1.
It will be accessed later via a read-only adapter using its Supabase PostgreSQL connection string.

---

## Current Status

**Current Phase:** Phase 1 — Foundation

**Phase 1 State:** Core implementation COMPLETE. Tests NOT yet written.

**Build Status:** `dotnet build` → **Build succeeded. 1 Warning. 0 Errors.**

**Migration Status:** `InitialCreate` migration generated and present in `src/Platform.Infrastructure/Persistence/Migrations/`

**Git Status:** Initial commit made. All Phase 1 source files committed.

---

## Architecture Decisions

### Platform Database
Separate PostgreSQL database from APIHunterV2.
APIHunter database and Platform database remain physically separate.

### Architecture Pattern
Clean Architecture:
```
Platform.Domain
  ↑
Platform.Application
  ↑
Platform.Infrastructure
  ↑
Platform.Api / Platform.Worker / Future Adapters
```

### Authentication
- Cookie-based (`__ap_session`) with ASP.NET Core authentication
- `PasswordHasher<User>` from Microsoft.AspNetCore.Identity — no custom crypto
- `IAntiforgery` CSRF via `X-CSRF-TOKEN` header
- `AuthenticationSession` entity — DB-backed, revocable sessions
- IP rate limiting + account lockout (`LockoutUntilUtc` on User)
- ASP.NET Core Data Protection for session key persistence

### Authorization Model
- `IsPlatformAdmin = true` bypasses ALL permission checks (still audited)
- Non-admins go through: Resource Auth → Permission Auth → Field Auth
- `FieldPermission.Effect = ALLOW | DENY` (not just ALLOW)
- DTO projection after field auth — no raw entity exposure

### Admin Bootstrap
- Idempotent — only runs if no admin user exists
- Does NOT reset password if admin already exists
- Controlled via `Seed__AdminEmail` / `Seed__AdminPassword` env vars

### Notification Provider Architecture
- `INotificationProvider` — adapter interface in Domain
- `IProviderSelector` — selects active provider based on `EMAIL_PROVIDER` env var
- All three providers always registered in DI; selector picks the active one
- Provider credentials encrypted via ASP.NET Core Data Protection
- `EMAIL_PROVIDER=smtp|sendgrid|mailgun`

### External Integrations
All external integrations MUST use adapters. Current interfaces:
- `INotificationProvider` ✅ (implemented)
- `IHealthComponent` ✅ (implemented)
- `ICurrentUserContext` ✅ (implemented)
- `IAuditService` ✅ (implemented)
- `IPlatformDbContext` ✅ (implemented)
- `IApiHunterSource` — Phase 2 (NOT YET CREATED)
- `IAiProvider` — Phase 3+ (NOT YET CREATED)
- `ISecurityScanner` — Phase 3+ (NOT YET CREATED)

### Workers
Stateless. One worker must be sufficient. Additional workers increase throughput.
Jobs must be durable and recoverable (Phase 2+ requirement).

---

## Phase 1 — What Was Actually Built

### Solution & Projects

| Project | Purpose | Status |
|---|---|---|
| `Platform.Domain` | Entities, Enums, Contracts, ValueObjects | ✅ Complete |
| `Platform.Application` | Use cases, Services, Configuration | ✅ Complete |
| `Platform.Infrastructure` | EF Core, Providers, Health | ✅ Complete |
| `Platform.Api` | ASP.NET Core 10 REST API | ✅ Complete |
| `Platform.Worker` | Background worker stub | ✅ Stub only |
| `Platform.UnitTests` | Unit test project | ⚠️ Scaffolded — no tests written |
| `Platform.IntegrationTests` | Integration test project | ⚠️ Scaffolded — no tests written |

### Domain Layer — `/src/Platform.Domain/`

**Entities:**
- `User.cs` — `Id`, `Email`, `Username`, `DisplayName`, `PasswordHash`, `IsPlatformAdmin`, `IsActive`, `LockoutUntilUtc`, `FailedLoginAttempts`, `CreatedAtUtc`
- `AuthenticationSession.cs` — `Id`, `UserId`, `IpAddress`, `UserAgent`, `ExpiresAtUtc`, `RevokedAtUtc`, `CreatedAtUtc`
- `Permission.cs` — Permission catalog: `Code`, `DisplayName`, `Description`, `Category`
- `UserPermission.cs` — join: `UserId` + `PermissionCode` + `GrantedAtUtc` + `GrantedByUserId`
- `FieldPermission.cs` — `PermissionCode`, `ResourceType`, `FieldName`, `Action`, `Effect` (ALLOW/DENY)
- `AuditEvent.cs` — `Id`, `EventCode`, `UserId`, `CorrelationId`, `IpAddress`, `Payload` (JSON), `CreatedAtUtc`
- `NotificationProviderConfig.cs` — encrypted provider credentials per channel
- `SystemSetting.cs` — key/value settings table

**Enums (`/Enums/`):**
- `DomainEnums.cs` — `NotificationChannel`, `AuditEventCode`
- `PermissionEffect.cs` — `Allow`, `Deny`
- Also: `FieldAction` (Read/Write), `NotificationProvider` (Smtp/SendGrid/Mailgun)

**Contracts (`/Contracts/`):**
- `INotificationProvider.cs` — `SendAsync`, `HealthCheckAsync`, `Channel`, `ProviderName`
- `INotificationService.cs` — `SendAsync`, `SendTestAsync`
- `ICurrentUserContext.cs` — `UserId`, `SessionId`, `IsAuthenticated`, `IsPlatformAdmin`, `CorrelationId`, `IpAddress`
- `IHealthComponent.cs` — `ComponentName`, `CheckAsync()` → `ComponentHealthResult`

**ValueObjects (`/ValueObjects/`):**
- `Notification.cs` — `RecipientEmail`, `RecipientName`, `Subject`, `Body`, `IsHtml`
- `ProviderHealthResult.cs` — `ProviderName`, `IsHealthy`, `Status`, `Detail`, `Latency`

### Application Layer — `/src/Platform.Application/`

**Configuration (`/Configuration/PlatformOptions.cs`):**
- `AuthenticationOptions` — session duration, lockout threshold, max concurrent sessions
- `DatabaseOptions`
- `CorsOptions`
- `DataProtectionOptions` (named `Platform.Application.Configuration.DataProtectionOptions` to avoid collision with ASP.NET's class)
- `RateLimitingOptions`
- `NotificationOptions` — `EmailProvider`
- `SmtpOptions`, `SendGridOptions`, `MailgunOptions`
- `SeedOptions` — `AdminEmail`, `AdminPassword`

**Services:**
- `AuthService.cs` — Login (lockout, session creation), Logout, GetUserSessions, RevokeSession
- `UserService.cs` — GetUsers (paginated), GetUserById, CreateUser, UpdateUser
- `PermissionService.cs` — GetAllPermissions, GetCallerPermissions, GetUserPermissions, SetUserPermissions, GetFieldPermissions, UpsertFieldPermission
- `AuditService.cs` — `RecordAsync(AuditEvent)`
- `AuditQueryService.cs` — paginated audit query with filtering
- `HealthAggregatorService.cs` — aggregates all `IHealthComponent` results
- `NotificationService.cs` — routes to active provider via `IProviderSelector`

**Common:**
- `Result<T>.cs` — `IsSuccess`, `Value`, `ErrorMessage`, `ErrorCode`
- `Pagination.cs` — `PaginationRequest`, `PaginatedResult<T>`

**Persistence:**
- `IPlatformDbContext.cs` — `DbSet<>` interface for all 8 entity sets

**Permissions:**
- `IProviderSelector.cs` — `SelectEmailProvider(providers)` interface
- `ICurrentUserContextProvider.cs`

### Infrastructure Layer — `/src/Platform.Infrastructure/`

**Persistence:**
- `PlatformDbContext.cs` — EF Core 10, all entities configured with indexes, constraints, `RowVersion` concurrency
- `DatabaseSeeder.cs` — idempotent admin + permission catalog bootstrap

**Migrations:**
- `InitialCreate` — created, includes all 8 tables with indexes and constraints

**Notifications:**
- `SmtpNotificationProvider.cs` — MailKit, TLS, real connection health check
- `SendGridNotificationProvider.cs` — Official SDK, scopes-based health check
- `MailgunNotificationProvider.cs` — US/EU region, domain-based health check, `IHttpClientFactory`
- `ProviderSelector.cs` — reads `EMAIL_PROVIDER`, returns matching provider

**Health:**
- `HealthComponents.cs` — `PostgresHealthComponent` (SELECT 1), `ApiHealthComponent` (version)

**Authentication:**
- `HttpCurrentUserContext.cs` — reads claims from ASP.NET cookie principal

### API Layer — `/src/Platform.Api/`

**Controllers:**
- `AuthController.cs` — Login, Logout, Me, GetSessions, RevokeSession, GetCsrfToken
- `UsersController.cs` — GetUsers, GetUser, CreateUser, UpdateUser [Admin only]
- `PermissionsController.cs` — GetMyPermissions, GetAllPermissions, GetUserPermissions, SetUserPermissions, GetFieldPermissions, UpsertFieldPermission
- `AuditController.cs` — GetAuditEvents (paginated, filtered) [Admin only]
- `HealthController.cs` — GET /health (public), GET /health/detailed [Admin only]
- `NotificationsController.cs` — GetProviderStatus, SendTestNotification [Admin only]

**Middleware:**
- `CorrelationIdMiddleware.cs` — injects/generates X-Correlation-ID, pushes to Serilog
- `ErrorHandlingMiddleware.cs` — suppresses stack traces in production, returns JSON error

**Auth Filters:**
- `AuthFilters.cs` — `[RequireAuth]` (401 JSON), `[RequireAdmin]` (403 JSON) — no redirect

**Program.cs:**
- Cookie auth + IAntiforgery CSRF
- ASP.NET Core Data Protection
- IP rate limiter (FixedWindow on login)
- CORS (configurable origins)
- IOptions<T> for all 10 config groups
- All services registered
- EF Core auto-migration + seeder on startup
- Serilog + OpenTelemetry
- Swagger (dev only)

### Infrastructure Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | PostgreSQL 16 + API + Next.js frontend |
| `deployment/docker/Dockerfile.api` | Multi-stage .NET 10 Docker build |
| `.env.example` | All environment variable documentation |
| `.gitignore` | Excludes .env, dp-keys, secrets, bin/obj |
| `README.md` | Quick start, architecture, API reference |

### Frontend — `/frontend/dashboard/`

- Next.js 15 + TypeScript + Tailwind CSS
- Design system: dark glassmorphic, Outfit/Inter/JetBrains Mono fonts, cyan accent palette
- Pages implemented:
  - `/` → redirect to `/login`
  - `/login` — cookie auth + CSRF token storage
  - `/dashboard` — stat cards, Phase 1 acceptance checklist
  - `/health` — overall + component health (admin detailed view)
  - `/settings/notifications` — provider health + test email
- Components: `Sidebar` (role-aware nav, logout with CSRF)
- Session check on every protected page — redirects to `/login` if unauthenticated

---

## Known Issues / Incomplete Items

### ⚠️ TESTS NOT WRITTEN
Unit and integration test projects are scaffolded (`Platform.UnitTests`, `Platform.IntegrationTests`) but contain only the default template `UnitTest1.cs`. No actual tests have been written.

**This is the #1 priority for the next session.**

### ⚠️ Frontend Pages Not Yet Built
The following pages are referenced in the sidebar but not yet implemented:
- `/users` — User management (CRUD)
- `/permissions` — User permission assignment
- `/audit` — Audit log viewer

### ⚠️ Notification Delivery History Not Tracked
`NotificationProviderConfig` entity exists but delivery tracking table is not yet implemented.

### ⚠️ AuthController Missing Usings
The `AuthController.cs` imports `Platform.Application.Users` for `LoginRequest` — this is a minor namespace issue that should be verified.

### ⚠️ NotificationsController Unused Parameter Warning
`currentUser` parameter in `NotificationsController` is unused (1 build warning). Will be used when field-level filtering is added.

### ⚠️ Admin Session Information Not Exposed in Me Endpoint
The `/api/v1/auth/me` endpoint returns `userId` and `isPlatformAdmin` but not `email` or `displayName`. Frontend may need this.

---

## Deferred (Phase 2+)

| Feature | Phase | Reason |
|---|---|---|
| APIHunter adapter (`IApiHunterSource`) | 2 | External system integration |
| APIHunter synchronization | 2 | Depends on adapter |
| Repository acquisition + indexing | 2 | Depends on adapter |
| Credential detection | 2 | Depends on repo indexing |
| Credential validation | 3 | Requires safe validation framework |
| Repository AI analysis | 3 | Requires AI Gateway |
| AI provider pool | 3 | Requires AI Gateway |
| Security Center / website scanning | 4 | Requires BugHunter/Burp adapters |
| JavaScript analysis | 4 | Separate scanner |
| BugHunter adapter | 4 | External tool |
| Burp agent | 4 | Optional local PC agent |
| Security findings | 4 | Depends on scanner |
| Email/Telegram security alerts | 3+ | Depends on notification provider |
| Operations AI | 3+ | Depends on AI Gateway |
| Durable jobs / outbox pattern | 2 | Platform.Worker |
| Object storage (Cloudflare R2) | 2+ | Repository artifact storage |

---

## Next Tasks (Priority Order)

1. **Write unit tests** for `AuthService`, `PermissionService`, `AuditService`, `NotificationService`, `HealthAggregatorService`
2. **Write integration tests** for auth flow (login, CSRF, logout, session revocation)
3. **Write authorization tests** — verify 401/403 behavior for all protected endpoints
4. **Build frontend `/users` page** — paginated user list + create/update
5. **Build frontend `/permissions` page** — user permission assignment
6. **Build frontend `/audit` page** — paginated audit log with filters
7. **Implement notification delivery history** table + tracking
8. **Add admin email to Me endpoint** response
9. Verify EF migration applies cleanly to a fresh PostgreSQL database

---

## Session History

## 2026-08-12 — Antigravity (Initial Build)

Completed:
- Full Phase 1 foundation implementation
- All 7 .NET projects scaffolded and cross-referenced
- All NuGet packages added and resolved
- 69 C# files written across Domain/Application/Infrastructure/API layers
- EF Core `InitialCreate` migration generated
- Next.js 15 dashboard scaffolded with 5 pages
- Initial git commit made
- `dotnet build` → Build succeeded. 0 Errors.

Tests:
- Test projects scaffolded but NO TESTS WRITTEN YET

Issues:
- 1 build warning: unused `currentUser` parameter in NotificationsController
- Frontend pages for `/users`, `/permissions`, `/audit` not yet built
- Delivery history not implemented

Decisions:
- See DECISIONS.md

Next:
- Write unit and integration tests (top priority)
- Build remaining frontend pages
