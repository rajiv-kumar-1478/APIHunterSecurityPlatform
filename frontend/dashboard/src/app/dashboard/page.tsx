"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { AppLayout } from "@/components/AppLayout";
import { apiRequest } from "@/lib/api-client";

interface CurrentUser {
  isPlatformAdmin: boolean;
  userId: string;
}

interface HealthSummary {
  status: string;
  isHealthy: boolean;
}

interface OperationalMetrics {
  systemHealth: string;
  activeIncidents: number;
  criticalIncidents: number;
  pendingJobs: number;
  runningJobs: number;
  overdueCampaigns: number;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [health, setHealth] = useState<HealthSummary | null>(null);
  const [ops, setOps] = useState<OperationalMetrics | null>(null);

  useEffect(() => {
    async function init() {
      try {
        const userData = await apiRequest<CurrentUser>("/api/v1/auth/me");
        setUser(userData);

        const healthData = await apiRequest<HealthSummary>("/api/v1/health");
        setHealth(healthData);

        try {
          const opsData = await apiRequest<OperationalMetrics>("/api/v1/operations/dashboard");
          setOps(opsData);
        } catch {
          // Operations metrics optional fallback
        }
      } catch {
        router.replace("/login");
      }
    }
    init();
  }, [router]);

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-[#7ba3c8] font-medium">Loading Security Dashboard…</p>
        </div>
      </div>
    );
  }

  const statCards = [
    {
      label: "Platform Health",
      value: health?.status ?? "Healthy",
      sub: health?.isHealthy ? "All services operational" : "Check health logs",
      badge: health?.isHealthy ? "Healthy" : "Degraded",
      badgeColor: health?.isHealthy ? "badge-healthy" : "badge-degraded",
      icon: (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
      ),
    },
    {
      label: "Active Incidents",
      value: ops?.activeIncidents ?? 0,
      sub: `${ops?.criticalIncidents ?? 0} critical severity`,
      badge: (ops?.criticalIncidents ?? 0) > 0 ? "Critical" : "Nominal",
      badgeColor: (ops?.criticalIncidents ?? 0) > 0 ? "badge-unhealthy" : "badge-healthy",
      icon: (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ff4757" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      ),
    },
    {
      label: "Running Scan Jobs",
      value: ops?.runningJobs ?? 0,
      sub: `${ops?.pendingJobs ?? 0} jobs in queue`,
      badge: "Active Workers",
      badgeColor: "badge-degraded",
      icon: (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2">
          <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
        </svg>
      ),
    },
    {
      label: "AI Router & Engine",
      value: "Active",
      sub: "Cohere + OpenAI + Anthropic",
      badge: "Multi-Provider",
      badgeColor: "badge-admin",
      icon: (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" strokeWidth="2">
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        </svg>
      ),
    },
  ];

  const quickActions = [
    {
      title: "Security Center",
      desc: "View findings, candidate secrets, and run security scans",
      href: "/security",
      icon: "🛡️",
      color: "#00d4ff",
    },
    {
      title: "Remediation Workflow",
      desc: "Approve policy recommendations and execute automated fixes",
      href: "/security/remediation",
      icon: "⚡",
      color: "#00ff88",
    },
    {
      title: "APIHunter Source Explorer",
      desc: "Browse incremental repository scans & key intelligence",
      href: "/apihunter",
      icon: "🔑",
      color: "#ffa502",
    },
    {
      title: "Credential Validation",
      desc: "Validate Cohere, OpenAI, AWS, Stripe & SendGrid endpoints",
      href: "/credentials",
      icon: "🔐",
      color: "#8b5cf6",
    },
    {
      title: "CI/CD Security Gate",
      desc: "Monitor active deployment leases and webhook evaluations",
      href: "/deployments",
      icon: "🚀",
      color: "#ff4757",
    },
    {
      title: "Operations AI Engine",
      desc: "Autonomous self-healing stream & LLM operational diagnosis",
      href: "/operations",
      icon: "🤖",
      color: "#00d4ff",
    },
  ];

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail="admin@apihunter.local"
      title="Security Intelligence Dashboard"
      subtitle="Real-time posture monitoring, AI secret detection & automated remediation engine"
      actions={
        <Link href="/security" className="btn-primary text-xs flex items-center gap-2">
          <span>Launch Scan</span>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <line x1="5" y1="12" x2="19" y2="12" />
            <polyline points="12 5 19 12 12 19" />
          </svg>
        </Link>
      }
    >
      {/* Stat Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 fade-in">
        {statCards.map((stat, i) => (
          <div key={i} className="glass-card stat-card-accent p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-[#4a6580]">
                {stat.label}
              </span>
              <span>{stat.icon}</span>
            </div>

            <div>
              <div className="flex items-baseline justify-between gap-2 mb-1">
                <span className="text-2xl font-bold tracking-tight text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
                  {stat.value}
                </span>
                <span className={`badge ${stat.badgeColor} text-[10px]`}>{stat.badge}</span>
              </div>
              <p className="text-xs text-[#7ba3c8]">{stat.sub}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Quick Action Hub */}
      <div className="space-y-4 fade-in">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            Platform Modules & Security Actions
          </h2>
          <span className="text-xs text-[#4a6580]">12 Core Modules Active</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {quickActions.map((action, i) => (
            <Link
              key={i}
              href={action.href}
              className="glass-card p-5 group flex flex-col justify-between hover:border-[#00d4ff]/40 transition-all duration-200"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-2xl p-2 rounded-xl bg-white/5">{action.icon}</span>
                  <span className="text-[#4a6580] group-hover:text-[#00d4ff] group-hover:translate-x-1 transition-all">
                    →
                  </span>
                </div>
                <h3 className="text-base font-semibold text-[#e8f4ff] group-hover:text-[#00d4ff] transition-colors mb-1" style={{ fontFamily: "Outfit, sans-serif" }}>
                  {action.title}
                </h3>
                <p className="text-xs text-[#7ba3c8] leading-relaxed">{action.desc}</p>
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Architecture & Core Capability Summary */}
      <div className="glass-card p-6 fade-in space-y-4">
        <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
          Platform Architecture & Security Coverage
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs text-[#7ba3c8]">
          <div className="p-4 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10 space-y-2">
            <span className="font-semibold text-[#00d4ff] block text-sm">Secret Detection Engine</span>
            <p>AST analysis, regex candidate matching, key versioning, and HMAC-SHA256 fingerprinting.</p>
          </div>
          <div className="p-4 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10 space-y-2">
            <span className="font-semibold text-[#8b5cf6] block text-sm">AI Router (v2 Cohere + Multi-LLM)</span>
            <p>Dynamic model router cascading across Cohere, Anthropic, DeepSeek, OpenAI, Groq & Gemini.</p>
          </div>
          <div className="p-4 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10 space-y-2">
            <span className="font-semibold text-[#00ff88] block text-sm">Autonomous Self-Healing</span>
            <p>Background workers handle stale lease recovery, job retries, and automated incident triage.</p>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}

