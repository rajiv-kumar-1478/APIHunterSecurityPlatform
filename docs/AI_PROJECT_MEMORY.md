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

**Current Phase:** Phase 1 — Foundation (COMPLETE)

**Phase 1 State:** Core implementation, unit tests, integration tests, and Next.js frontend pages are 100% COMPLETE & VERIFIED.

**Build Status:**
- `dotnet build` → **Build succeeded. 0 Errors.**
- `npm run build` (Next.js) → **Compiled successfully in 9.6s. 0 Errors.**

**Test Status:**
- `Platform.UnitTests`: **12 / 12 Passed** (Duration: 832 ms)
- `Platform.IntegrationTests`: **3 / 3 Passed** (Duration: 1 s)

**Migration Status:** `InitialCreate` migration generated and present in `src/Platform.Infrastructure/Persistence/Migrations/`

**Git Status:** All Phase 1 source files, tests, docs, and Next.js pages committed.

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
- `FieldPermission.Effect = ALLOW | DENY`
- DTO projection after field auth — no raw entity exposure

### Admin Bootstrap
- Idempotent — only runs if no admin user exists
- Does NOT reset password if admin already exists
- Controlled via `Seed__AdminEmail` / `Seed__AdminPassword` env vars

### Notification Provider Architecture
- `INotificationProvider` — adapter interface in Domain
- `IProviderSelector` — selects active provider based on `EMAIL_PROVIDER` env var
- All three providers always registered in DI; selector picks active one
- Provider credentials encrypted via ASP.NET Core Data Protection
- `EMAIL_PROVIDER=smtp|sendgrid|mailgun`

---

## Phase 1 — Verified Components

| Component | Status | Verification |
|---|---|---|
| Domain Models & Contracts | ✅ Complete | Compiled & unit tested |
| Application Services & DTOs | ✅ Complete | Unit tested (12 tests) |
| Infrastructure & EF Core DB Context | ✅ Complete | EF Migration `InitialCreate` generated |
| ASP.NET Core 10 Web API | ✅ Complete | Integration tested (3 tests) |
| AuthService & Password Hashing | ✅ Complete | Unit tested |
| PermissionService & Field Auth | ✅ Complete | Unit tested |
| HealthAggregatorService | ✅ Complete | Unit tested |
| UserService CRUD | ✅ Complete | Unit tested |
| Next.js 15 Frontend Dashboard | ✅ Complete | `npm run build` static & dynamic routes compiled |

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

## Next Task (Phase 2)

**Phase 2 — APIHunter Adapter & Discovery Synchronization**
- Implement `IApiHunterSource` read-only adapter connecting to legacy Supabase PostgreSQL
- Import API keys (`Valid`, `ValidNoCredits`), repositories, and search queries
- Display discovered credentials on dashboard (masked by default, with `credential.reveal` permission guard)

---

## Session History

## 2026-08-12 — Antigravity (Phase 1 Finalization & Test Suite)

Completed:
- Created required project documents: `AI_DEVELOPMENT_RULES.md`, `AI_PROJECT_MEMORY.md`, `IMPLEMENTATION_STATUS.md`, `DECISIONS.md`.
- Implemented unit test suite in `tests/Platform.UnitTests` covering `AuthService`, `PermissionService`, `HealthAggregatorService`, `UserService`.
- Implemented integration test suite in `tests/Platform.IntegrationTests` using `WebApplicationFactory<Program>` with in-memory DB & testing environment host setup.
- Built remaining Next.js frontend pages: `/users` (User Management), `/permissions` (Permission Catalog & Field Level Rules), `/audit` (Audit Log Viewer).
- Executed `dotnet test`: 15 / 15 tests passed (12 unit, 3 integration).
- Executed `npm run build` inside `frontend/dashboard`: Compiled successfully in 9.6s with 0 errors.

Tests:
- Unit Tests: 12 Passed (0 Failed)
- Integration Tests: 3 Passed (0 Failed)

Decisions:
- Updated `Program.cs` DB migration logic to check `IsRelational()` for compatibility with in-memory test databases.
- Updated `Program.cs` with `public partial class Program { }` marker for `WebApplicationFactory`.

Next:
- Begin Phase 2 — APIHunter Adapter & Discovery Synchronization.
