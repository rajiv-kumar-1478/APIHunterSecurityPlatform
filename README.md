# APIHunter Security Intelligence Platform

> Phase 1 — Foundation | .NET 10 + EF Core 10 + Next.js 15 | Production-grade security dashboard

---

## Quick Start (Local Development)

### Prerequisites
- .NET 10 SDK
- Node.js 20+ / npm
- PostgreSQL 16+ (or use Docker Compose)
- Docker (optional)

### 1. Clone and configure

```bash
cd C:\Users\rk170\Desktop\APIHunterSecurityPlatform
copy .env.example .env
# Edit .env — set ADMIN_EMAIL, ADMIN_PASSWORD, DB connection
```

### 2. Start with Docker Compose (easiest)

```bash
docker compose up -d
```

- API: http://localhost:5000
- Frontend: http://localhost:3000
- Swagger: http://localhost:5000/swagger

### 3. Or run locally

```bash
# Terminal 1 — Database (if not using Docker)
docker run -e POSTGRES_DB=platform_db -e POSTGRES_USER=platform -e POSTGRES_PASSWORD=changeme -p 5432:5432 postgres:16-alpine

# Terminal 2 — API
cd src/Platform.Api
dotnet run

# Terminal 3 — Frontend
cd frontend/dashboard
npm install
npm run dev
```

---

## Architecture

```
Platform.Domain          ← Entities, Enums, Contracts, ValueObjects (no external deps)
Platform.Application     ← Use cases, Services, DTOs (depends on Domain only)
Platform.Infrastructure  ← EF Core, Postgres, Notifications, Health (depends on Application)
Platform.Api             ← ASP.NET Core 10 REST API
Platform.Worker          ← Background worker stub (Phase 2+)

frontend/dashboard       ← Next.js 15 + React + TypeScript + Tailwind
```

## Authentication

- **Cookie-based sessions** — `__ap_session` (HttpOnly, Secure in prod)
- **CSRF protection** — `X-CSRF-TOKEN` header required on all state-changing requests
- **ASP.NET Core Data Protection** — key persistence via `DataProtection:KeyPath` env var
- **PasswordHasher<User>** — Microsoft.AspNetCore.Identity hashing (no custom crypto)
- **Brute-force protection** — IP rate limiting + account lockout after N failures

## Authorization

```
Authentication → Resource Auth → Permission Auth → Field Auth → DTO Projection → Response
```

- `IsPlatformAdmin = true` → bypasses all permission checks (still audited)
- Field permissions support `ALLOW` / `DENY` effects

## Email Notifications

Set `EMAIL_PROVIDER=smtp|sendgrid|mailgun` in your environment:

| Provider | Required Env Vars |
|----------|------------------|
| smtp     | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` |
| sendgrid | `SENDGRID_API_KEY`, `SENDGRID_FROM` |
| mailgun  | `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_REGION` (us/eu), `MAILGUN_FROM` |

Test from Admin dashboard: **Settings → Notifications → Send Test**

## API Endpoints (Phase 1)

```
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{id}
GET    /api/v1/auth/csrf

GET    /api/v1/users                        [Admin]
POST   /api/v1/users                        [Admin]
PATCH  /api/v1/users/{id}                   [Admin]

GET    /api/v1/permissions                  [Auth — own permissions]
GET    /api/v1/admin/permissions            [Admin — full catalog]
GET    /api/v1/admin/users/{id}/permissions [Admin]
PUT    /api/v1/admin/users/{id}/permissions [Admin]
GET    /api/v1/admin/field-permissions      [Admin]
PUT    /api/v1/admin/field-permissions      [Admin]

GET    /api/v1/audit                        [Admin]

GET    /api/v1/health                       [Public]
GET    /api/v1/health/detailed              [Admin]

GET    /api/v1/notifications/providers      [Admin]
POST   /api/v1/notifications/test           [Admin]

GET    /swagger                             [Dev only]
```

## Phase 2 (Next)

- APIHunter adapter → read-only connection to existing Supabase PostgreSQL
- Import APIKeys, RepoReferences, SearchQueries
- Display discovered keys in dashboard (masked by default)
- `credential.reveal` permission for unmasking

---

## Security Checklist

- [x] No secrets in repository
- [x] `.env` in `.gitignore`
- [x] Encrypted notification provider configs
- [x] HttpOnly + Secure session cookies (production)
- [x] CSRF antiforgery on all mutations
- [x] Error responses suppress stack traces in production
- [x] CORS restricted to configured origins
- [x] IP rate limiting + account lockout
