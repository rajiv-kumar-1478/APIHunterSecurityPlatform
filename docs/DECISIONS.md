# Architecture Decision Log — APIHunter Security Intelligence Platform

---

## DEC-001: Separate Repository & Database for Platform
- **Date**: 2026-08-12
- **Title**: Physical Separation of Platform and APIHunterV2
- **Context**: The user requested a new web-based security intelligence platform while keeping the existing APIHunter application untouched.
- **Decision**: Create a brand new repository at `C:\Users\rk170\Desktop\APIHunterSecurityPlatform\` with its own PostgreSQL database. Do not modify or depend directly on `APIHunterV2` during Phase 1.
- **Alternatives**: Shared codebase or shared DB schema. Rejected to prevent breaking existing crawler logic.
- **Impact**: Platform remains cleanly isolated. APIHunterV2 will be connected in Phase 2 via read-only adapter contracts.

---

## DEC-002: Tech Stack Selection
- **Date**: 2026-08-12
- **Title**: .NET 10 + EF Core 10 + Next.js 15
- **Context**: Selecting LTS runtime and modern web frontend stack.
- **Decision**: Use .NET 10 Web API backend, EF Core 10 ORM, PostgreSQL database, and Next.js 15 (App Router) + Tailwind CSS frontend.
- **Impact**: Provides supported long-term foundation through 2028.

---

## DEC-003: Cookie Authentication + Anti-Forgery CSRF
- **Date**: 2026-08-12
- **Title**: Cookie-based Session Authentication with CSRF Tokens
- **Context**: Securing browser-to-backend communication for the management dashboard.
- **Decision**: Use HTTP-only SameSite cookies (`__ap_session`) backed by DB-persisted `AuthenticationSession` records, combined with ASP.NET Core `IAntiforgery` tokens sent via `X-CSRF-TOKEN` headers.
- **Impact**: Complete protection against CSRF and XSS token theft. Allows instant session revocation by admin or user.

---

## DEC-004: Password Hashing Standard
- **Date**: 2026-08-12
- **Title**: Use Microsoft.AspNetCore.Identity.PasswordHasher<TUser>
- **Context**: Avoiding custom password hashing implementations.
- **Decision**: Delegate all password hashing and verification to `IPasswordHasher<User>` (`PasswordHasher<User>`).
- **Impact**: Complies with PBKDF2/HMAC-SHA256 standards with work factors managed by .NET framework updates.

---

## DEC-005: Authorization & Field-Level Security Model
- **Date**: 2026-08-12
- **Title**: Platform Admin Bypass & Explicit ALLOW/DENY Field Permissions
- **Context**: Granular RBAC and field visibility control for sensitive security data.
- **Decision**: `IsPlatformAdmin = true` bypasses permission evaluations (audited). Non-admins evaluate explicit `Permission` records and `FieldPermission` rules with `ALLOW` or `DENY` effects. DTO projection occurs after authorization.
- **Impact**: Security boundaries enforced strictly on server side.

---

## DEC-006: Multi-Provider Notification Architecture
- **Date**: 2026-08-12
- **Title**: Adapter-Based Notification Infrastructure with Health Probes
- **Context**: Need flexible notification channels (SMTP, SendGrid, Mailgun) for alerts.
- **Decision**: Implement `INotificationProvider` adapters for MailKit SMTP, SendGrid SDK, and Mailgun API. All providers registered in DI. `ProviderSelector` routes traffic based on `EMAIL_PROVIDER` configuration.
- **Impact**: Zero code changes required to swap email delivery providers.

---

## DEC-007: Read-Only APIHunter Integration & Adapter Pattern
- **Date**: 2026-08-12
- **Title**: Decoupled Read-Only PostgreSQL Adapter & Normalized Synchronization
- **Context**: Need to import intelligence credentials from APIHunterV2 without modifying its database schema or executing write queries against its database.
- **Decision**: Define `IApiHunterSource` and `IApiHunterStatusMapper` contracts. Read-only PostgreSQL connection fetches APIKeys and RepoReferences incrementally. `ApiHunterSyncService` normalizes records, masks raw keys by default, encrypts raw keys at rest via Data Protection, deduplicates entity insertion by source ID, and audits reveal actions.
- **Impact**: APIHunterV2 database remains 100% read-only and decoupled from Platform business logic. Schema changes in APIHunterV2 can be handled inside `ApiHunterAdapter` without touching domain entities.
