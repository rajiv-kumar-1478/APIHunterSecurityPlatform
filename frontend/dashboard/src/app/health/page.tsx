"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

import { apiRequest } from "@/lib/api-client";

interface ComponentHealth {
  name: string;
  isHealthy: boolean;
  status: string;
  detail?: string;
  latencyMs?: number;
}

interface HealthReport {
  status: string;
  isHealthy: boolean;
  checkedAt: string;
  components: ComponentHealth[];
}

interface ScannerRuntimeHealth {
  status: "Healthy" | "Degraded" | "Unavailable" | "NotConfigured" | "FailClosed" | string;
  runtime: {
    mode: string;
    available: boolean;
    version: string;
  };
  sandbox?: {
    sandboxIsolated: boolean;
    proxyEnforced: boolean;
    limitsApplied: boolean;
  };
  provenance: {
    imageDigestRequired: boolean;
    trustedRegistries: string[];
  };
  egress: {
    mode: string;
    enforced: boolean;
    gatewayHealthy: boolean;
    gatewayEndpoint: string;
  };
  limits: {
    cpuCores: number;
    memoryBytes: number;
    pids: number;
    scratchBytes: number;
    timeoutSeconds: number;
  };
  activeJobsCount: number;
  readyForScans: boolean;
  diagnostics?: string[];
  lastHealthCheckUtc: string;
}

export default function HealthPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean } | null>(null);
  const [report, setReport] = useState<HealthReport | null>(null);
  const [scannerHealth, setScannerHealth] = useState<ScannerRuntimeHealth | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiRequest<{ isPlatformAdmin: boolean }>("/api/v1/auth/me");
        setUser(me);

        await fetchAllHealth(me.isPlatformAdmin);
        setLoading(false);
      } catch {
        router.replace("/login");
      }
    }
    init();
  }, [router]);

  async function fetchAllHealth(isAdmin: boolean) {
    try {
      if (isAdmin) {
        const healthReport = await apiRequest<HealthReport>("/api/v1/health/detailed");
        setReport(healthReport);
      } else {
        const healthReport = await apiRequest<Omit<HealthReport, "components">>("/api/v1/health");
        setReport({ ...healthReport, components: [] });
      }

      const scannerReport = await apiRequest<ScannerRuntimeHealth>("/api/v1/security/scans/runtime/health");
      setScannerHealth(scannerReport);
    } catch (error: unknown) {
      console.error("Failed to fetch health reports", error);
    }
  }

  async function refresh() {
    setLoading(true);
    await fetchAllHealth(user?.isPlatformAdmin ?? false);
    setLoading(false);
  }

  if (!user) return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-8 h-8 border-2 border-current border-t-transparent rounded-full animate-spin"
        style={{ color: "var(--accent-cyan)" }} />
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar isAdmin={user.isPlatformAdmin} />
      <main className="flex-1 overflow-auto p-8">
        <div className="flex items-center justify-between mb-8 fade-in">
          <div>
            <h1 className="text-2xl font-bold" style={{ fontFamily: "Outfit, sans-serif" }}>
              System Health & Scanner Observability
            </h1>
            <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
              {report?.checkedAt ? `Last checked: ${new Date(report.checkedAt).toLocaleTimeString()}` : "Real-time component status & security runtime boundaries"}
            </p>
          </div>
          <button className="btn-ghost" onClick={refresh} disabled={loading}>
            {loading ? "Refreshing…" : "↻ Refresh"}
          </button>
        </div>

        {/* Overall status */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6 fade-in">
          <div className="glass-card stat-card-accent p-6">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-xl flex items-center justify-center text-2xl"
                style={{ background: report?.isHealthy ? "var(--accent-green-dim)" : "var(--accent-red-dim)" }}>
                {report?.isHealthy ? "✅" : "⚠️"}
              </div>
              <div>
                <p className="text-xl font-bold" style={{
                  fontFamily: "Outfit, sans-serif",
                  color: report?.isHealthy ? "var(--accent-green)" : "var(--accent-red)"
                }}>
                  {report?.status ?? "—"}
                </p>
                <p className="text-sm" style={{ color: "var(--text-muted)" }}>Overall platform status</p>
              </div>
            </div>
          </div>

          {/* Scanner Sandbox Operational Readiness */}
          <div className="glass-card stat-card-accent p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-xl flex items-center justify-center text-2xl"
                  style={{ background: scannerHealth?.readyForScans ? "var(--accent-green-dim)" : "var(--accent-red-dim)" }}>
                  {scannerHealth?.readyForScans ? "🛡️" : "⚠️"}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-xl font-bold" style={{
                      fontFamily: "Outfit, sans-serif",
                      color: scannerHealth?.readyForScans ? "var(--accent-green)" : "var(--accent-red)"
                    }}>
                      {scannerHealth?.readyForScans ? "READY FOR SCANS" : "NOT READY FOR SCANS"}
                    </p>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${
                      scannerHealth?.status === "Healthy" ? "bg-emerald-950 text-emerald-300 border border-emerald-700" :
                      scannerHealth?.status === "Degraded" ? "bg-amber-950 text-amber-300 border border-amber-700" :
                      scannerHealth?.status === "NotConfigured" ? "bg-indigo-950 text-indigo-300 border border-indigo-700" :
                      "bg-rose-950 text-rose-300 border border-rose-700"
                    }`}>
                      {scannerHealth?.status ?? "Unavailable"}
                    </span>
                  </div>
                  <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                    Scanner Runtime Sandbox & Egress Boundary
                  </p>
                </div>
              </div>
              <span className={`badge ${scannerHealth?.readyForScans ? "badge-healthy" : "badge-unhealthy"}`}>
                {scannerHealth?.runtime.mode ?? "LocalDocker"}
              </span>
            </div>
          </div>
        </div>

        {/* Scanner Runtime & Egress Gateway Card */}
        {scannerHealth && (
          <div className="glass-card p-6 mb-6 fade-in">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-semibold" style={{ fontFamily: "Outfit, sans-serif" }}>
                  Scanner Runtime Sandbox & Egress Boundary
                </h2>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Deterministic security boundary status & resource constraints
                </p>
              </div>
              <span className="text-xs mono" style={{ color: "var(--text-muted)" }}>
                {scannerHealth.runtime.version}
              </span>
            </div>

            {/* Diagnostic Callout Messages */}
            {scannerHealth.diagnostics && scannerHealth.diagnostics.length > 0 && (
              <div className={`p-4 rounded-xl mb-6 border ${
                scannerHealth.readyForScans
                  ? "bg-emerald-950/30 border-emerald-800 text-emerald-200"
                  : "bg-rose-950/30 border-rose-800 text-rose-200"
              }`}>
                <div className="flex items-center gap-2 mb-1">
                  <span>{scannerHealth.readyForScans ? "✅" : "⚠️"}</span>
                  <span className="font-semibold text-xs uppercase tracking-wider">
                    {scannerHealth.readyForScans ? "Runtime Operational Diagnostics" : "Critical Security Runtime Warning"}
                  </span>
                </div>
                <ul className="text-xs space-y-1 list-disc list-inside opacity-90">
                  {scannerHealth.diagnostics.map((diag, i) => (
                    <li key={i}>{diag}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
              <div className="p-3 rounded-xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  {scannerHealth.runtime.mode === "CloudManagedContainer" ? "Cloud Service" : "Docker Daemon"}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-2 h-2 rounded-full" style={{ background: scannerHealth.runtime.available ? "var(--accent-green)" : "var(--accent-red)" }} />
                  <span className="text-sm font-semibold">{scannerHealth.runtime.available ? "AVAILABLE" : "OFFLINE"}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>Image Provenance</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-2 h-2 rounded-full" style={{ background: scannerHealth.provenance.imageDigestRequired ? "var(--accent-green)" : "var(--accent-yellow)" }} />
                  <span className="text-sm font-semibold">{scannerHealth.provenance.imageDigestRequired ? "ENFORCED" : "OPTIONAL"}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>Egress Gateway</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-2 h-2 rounded-full" style={{ background: scannerHealth.egress.gatewayHealthy ? "var(--accent-green)" : "var(--accent-red)" }} />
                  <span className="text-sm font-semibold">{scannerHealth.egress.gatewayHealthy ? "ENFORCED" : "OFFLINE"}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>Sandbox Isolation</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-2 h-2 rounded-full" style={{ background: scannerHealth.sandbox?.sandboxIsolated !== false ? "var(--accent-cyan)" : "var(--accent-red)" }} />
                  <span className="text-sm font-semibold">{scannerHealth.sandbox?.sandboxIsolated !== false ? "ISOLATED" : "UNSAFE"}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>Active Scan Jobs</p>
                <p className="text-sm font-semibold mt-1">{scannerHealth.activeJobsCount} Active</p>
              </div>
            </div>

            {/* Sandbox Resource Limits */}
            <div className="pt-4 border-t border-border-subtle">
              <p className="text-xs font-medium mb-3" style={{ color: "var(--text-muted)" }}>
                SANDBOX ENFORCEMENT LIMITS
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 text-center">
                <div className="p-2 rounded-lg bg-surface-subtle">
                  <p className="text-xs text-muted">CPU Limit</p>
                  <p className="text-sm font-bold mono">{scannerHealth.limits.cpuCores} Cores</p>
                </div>
                <div className="p-2 rounded-lg bg-surface-subtle">
                  <p className="text-xs text-muted">Memory Limit</p>
                  <p className="text-sm font-bold mono">{(scannerHealth.limits.memoryBytes / (1024 * 1024 * 1024)).toFixed(1)} GB</p>
                </div>
                <div className="p-2 rounded-lg bg-surface-subtle">
                  <p className="text-xs text-muted">PID Limit</p>
                  <p className="text-sm font-bold mono">{scannerHealth.limits.pids} PIDs</p>
                </div>
                <div className="p-2 rounded-lg bg-surface-subtle">
                  <p className="text-xs text-muted">Scratch Disk</p>
                  <p className="text-sm font-bold mono">{(scannerHealth.limits.scratchBytes / (1024 * 1024)).toFixed(0)} MB</p>
                </div>
                <div className="p-2 rounded-lg bg-surface-subtle">
                  <p className="text-xs text-muted">Timeout</p>
                  <p className="text-sm font-bold mono">{scannerHealth.limits.timeoutSeconds}s</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Components (Admin only) */}
        {user.isPlatformAdmin && report?.components && report.components.length > 0 && (
          <div className="glass-card p-6 fade-in">
            <h2 className="text-lg font-semibold mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>
              Component Health
            </h2>
            <div className="space-y-3">
              {report.components.map((comp, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-xl"
                  style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full"
                      style={{ background: comp.isHealthy ? "var(--accent-green)" : "var(--accent-red)" }} />
                    <p className="font-medium text-sm" style={{ color: "var(--text-primary)" }}>{comp.name}</p>
                    {comp.detail && <p className="text-xs" style={{ color: "var(--text-muted)" }}>{comp.detail}</p>}
                  </div>
                  <div className="flex items-center gap-3">
                    {comp.latencyMs !== undefined && (
                      <p className="text-xs mono" style={{ color: "var(--text-muted)" }}>
                        {comp.latencyMs.toFixed(1)}ms
                      </p>
                    )}
                    <span className={`badge ${comp.isHealthy ? "badge-healthy" : "badge-unhealthy"}`}>
                      {comp.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {!user.isPlatformAdmin && (
          <div className="glass-card p-6 fade-in">
            <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
              Detailed component health is available to Platform Admins only.
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
