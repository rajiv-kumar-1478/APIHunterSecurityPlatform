"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

import { apiRequest } from "@/lib/api-client";

interface CurrentUser {
  isPlatformAdmin: boolean;
  userId: string;
}

interface HealthSummary {
  status: string;
  isHealthy: boolean;
}

interface StatCard {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color: string;
  sub?: string;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [health, setHealth] = useState<HealthSummary | null>(null);

  useEffect(() => {
    async function init() {
      try {
        const data = await apiRequest<CurrentUser>("/api/v1/auth/me");
        setUser(data);

        const healthData = await apiRequest<HealthSummary>("/api/v1/health");
        setHealth(healthData);
      } catch {
        router.replace("/login");
      }
    }
    init();
  }, [router]);

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-current border-t-transparent rounded-full animate-spin"
          style={{ color: "var(--accent-cyan)" }} />
      </div>
    );
  }

  const stats: StatCard[] = [
    {
      label: "Platform Status",
      value: health?.status ?? "Loading…",
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>,
      color: health?.isHealthy ? "var(--accent-green)" : "var(--accent-red)",
      sub: "API + Database",
    },
    {
      label: "Phase",
      value: "1 — Foundation",
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>,
      color: "var(--accent-cyan)",
      sub: "Auth + Permissions + Audit",
    },
    {
      label: "Access Level",
      value: user.isPlatformAdmin ? "Platform Admin" : "User",
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>,
      color: user.isPlatformAdmin ? "var(--accent-purple)" : "var(--accent-cyan)",
      sub: user.isPlatformAdmin ? "Full access" : "Restricted access",
    },
    {
      label: "Phase 2",
      value: "Coming Soon",
      icon: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>,
      color: "var(--text-muted)",
      sub: "APIHunter Integration",
    },
  ];

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar isAdmin={user.isPlatformAdmin} />

      <main className="flex-1 overflow-auto p-8">
        {/* Header */}
        <div className="mb-8 fade-in">
          <h1 className="text-3xl font-bold mb-1"
            style={{ fontFamily: "Outfit, sans-serif" }}>
            <span className="gradient-text">Security Intelligence</span> Platform
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
            Phase 1 Foundation — Authentication, Permissions & Audit
          </p>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8 fade-in">
          {stats.map((stat, i) => (
            <div key={i} className="glass-card stat-card-accent p-5">
              <div className="flex items-center justify-between mb-3">
                <p className="text-xs font-medium" style={{ color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.8px" }}>
                  {stat.label}
                </p>
                <span style={{ color: stat.color }}>{stat.icon}</span>
              </div>
              <p className="text-xl font-bold mb-1" style={{ fontFamily: "Outfit, sans-serif", color: stat.color }}>
                {stat.value}
              </p>
              {stat.sub && <p className="text-xs" style={{ color: "var(--text-muted)" }}>{stat.sub}</p>}
            </div>
          ))}
        </div>

        {/* Phase 1 checklist */}
        <div className="glass-card p-6 fade-in">
          <h2 className="text-lg font-semibold mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>
            Phase 1 — Acceptance Checklist
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              ["✅", "dotnet build succeeds (0 errors)"],
              ["✅", "EF Core migration created"],
              ["✅", "PasswordHasher<User> — no custom hashing"],
              ["✅", "CSRF antiforgery (X-CSRF-TOKEN)"],
              ["✅", "IP + Account rate limiting + lockout"],
              ["✅", "IsPlatformAdmin bypass model"],
              ["✅", "FieldPermission ALLOW/DENY effect"],
              ["✅", "AuthenticationSession (DB-backed)"],
              ["✅", "AuditEvent with CorrelationId"],
              ["✅", "IHealthComponent abstraction"],
              ["✅", "SMTP / SendGrid / Mailgun providers"],
              ["✅", "ProviderSelector (EMAIL_PROVIDER env)"],
              ["✅", "SystemSetting table seeded"],
              ["✅", "NotificationProviderConfig (encrypted)"],
              ["✅", "Serilog structured logs"],
              ["✅", "X-Correlation-ID middleware"],
              ["✅", "OpenTelemetry foundation"],
              ["✅", "Swagger/OpenAPI in dev"],
              ["✅", "Cookie: HttpOnly + Secure (prod)"],
              ["✅", "Next.js dashboard shell connected"],
            ].map(([icon, label], i) => (
              <div key={i} className="flex items-center gap-2 text-sm" style={{ color: "var(--text-secondary)" }}>
                <span style={{ fontSize: "16px" }}>{icon}</span>
                <span>{label}</span>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
