# SPEC-001-PHASE-1-LOCKED — Phase 1 Acceptance Criteria & Specification

> **LOCKED ARCHITECTURE CONTRACT — DO NOT ALTER WITHOUT ARCHITECT APPROVAL**

---

# System Goal & Scope

Build a separate, web-based security intelligence platform around the existing APIHunter system.

The platform provides:
- APIHunter dashboard
- APIHunter command/job management
- APIHunter discovery synchronization
- `Valid` / `ValidNoCredits` repository investigation
- Whole-repository AI analysis
- Verified credential analysis

---

# Locked Phase 1 — Foundation Requirements

## Architecture & Framework
- **Runtime**: .NET 10 + EF Core 10 + PostgreSQL
- **Frontend**: Next.js 15 App Router + TypeScript + Tailwind CSS
- **Design Pattern**: Clean Architecture (Domain → Application → Infrastructure → API/Adapters)
- **Isolation**: Physical separation from `APIHunterV2` repository. `APIHunterV2` remains untouched in Phase 1.

## Authentication & Session Management
- **Auth Model**: Cookie-based session authentication (`__ap_session`)
- **Password Hashing**: `Microsoft.AspNetCore.Identity.PasswordHasher<User>` (PBKDF2/HMAC-SHA256)
- **Sessions**: DB-persisted `AuthenticationSession` entity with session expiry and revocation endpoints
- **Brute-force Protection**: IP rate limiting (FixedWindow) + Account lockout (`LockoutUntilUtc` & `FailedLoginCount`)
- **CSRF Protection**: ASP.NET Core `IAntiforgery` with `X-CSRF-TOKEN` header on all mutation endpoints
- **Data Protection**: ASP.NET Core Data Protection key persistence (`DataProtection:KeyPath`)
- **Admin Bootstrap**: Idempotent bootstrap on startup if no admin user exists

## Authorization & Security Boundaries
- **Platform Admin**: `IsPlatformAdmin = true` bypasses permission checks (audited)
- **Role & Permission Model**: Permission catalog + UserPermission assignment
- **Field-Level Security**: `FieldPermission` with explicit `ALLOW` and `DENY` effects
- **DTO Projection**: Server-side filtering before serialization. Protected data is never sent to the frontend.

## Audit & Observability
- **Audit System**: Immutable `AuditEvent` records with JSON payload and correlation ID
- **Correlation ID**: `X-Correlation-ID` middleware attached to all logs, traces, and audit events
- **Logging**: Serilog structured logging with sensitive data redaction
- **OpenTelemetry**: ASP.NET Core tracing and metrics registration

## Health & Infrastructure
- **Component-Based Health**: `IHealthComponent` abstraction
- **Components**: PostgreSQL health (`SELECT 1`), API health (version check)
- **Health Endpoints**: Public probe (`/api/v1/health`), Admin breakdown (`/api/v1/health/detailed`)

## Notification Architecture
- **Adapter Contract**: `INotificationProvider` interface (Domain)
- **Providers**: `SmtpNotificationProvider` (MailKit + TLS), `SendGridNotificationProvider` (SDK), `MailgunNotificationProvider` (HTTP API + regions)
- **Provider Selector**: `ProviderSelector` class choosing provider based on `EMAIL_PROVIDER` environment variable
- **Encrypted Config**: `NotificationProviderConfig` credentials encrypted at rest
- **Health & Testing**: Provider health probes and `/api/v1/notifications/test` endpoint

---

# Required Phase 1 Acceptance Checklist

*Every item below represents a mandatory acceptance criterion to be verified independently via Code + Config + Test + Runtime Execution:*

- [x] .NET 10 Solution & 6 Projects scaffolded with Clean Architecture rules
- [x] PostgreSQL PlatformDbContext with 8 core entity tables & indexes
- [x] EF Core `InitialCreate` migration generated and applied cleanly
- [x] PasswordHasher<User> used for all password operations (no custom crypto)
- [x] Cookie authentication with HttpOnly and Secure policies
- [x] CSRF protection with `IAntiforgery` and `X-CSRF-TOKEN` header validation
- [x] Account lockout after N failed attempts + IP rate limiting
- [x] DB-backed `AuthenticationSession` tracking, listing, and revocation
- [x] Idempotent Admin bootstrap on startup
- [x] `IsPlatformAdmin` authorization bypass model (audited)
- [x] Field-level permissions with `ALLOW` and `DENY` effects
- [x] Immutable `AuditEvent` recording with correlation ID tracking
- [x] Component-based health check abstraction (`IHealthComponent`)
- [x] PostgreSQL & API health components implemented
- [x] `INotificationProvider` adapters for SMTP, SendGrid, and Mailgun
- [x] `ProviderSelector` routing based on `EMAIL_PROVIDER` configuration
- [x] Encrypted `NotificationProviderConfig` for credentials at rest
- [x] Serilog structured logging with `X-Correlation-ID` enrichment
- [x] OpenTelemetry tracing and metrics instrumentation
- [x] OpenAPI / Swagger documentation enabled in development
- [x] Next.js 15 dashboard shell with dark glassmorphic UI and React 19 app router
- [x] Next.js pages: `/login`, `/dashboard`, `/health`, `/users`, `/permissions`, `/audit`, `/settings/notifications`
- [x] Unit test suite (`Platform.UnitTests`) passing
- [x] Integration test suite (`Platform.IntegrationTests`) passing
- [x] Docker Compose deployment configuration (`docker-compose.yml`)
