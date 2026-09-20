"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
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
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; email?: string } | null>(null);
  const [report, setReport] = useState<HealthReport | null>(null);
  const [scannerHealth, setScannerHealth] = useState<ScannerRuntimeHealth | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiRequest<{ isPlatformAdmin: boolean; email?: string }>("/api/v1/auth/me");
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
    <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
      <div className="flex flex-col items-center gap-3">
        <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
        <p className="text-xs text-[#7ba3c8] font-medium">Loading System Health…</p>
      </div>
    </div>
  );

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="System Health & Observability"
      subtitle={report?.checkedAt ? `Last checked: ${new Date(report.checkedAt).toLocaleTimeString()}` : "Real-time component status & security runtime boundaries"}
      actions={
        <button className="btn-secondary text-xs flex items-center gap-2" onClick={refresh} disabled={loading}>
          <span>{loading ? "Refreshing…" : "↻ Refresh"}</span>
        </button>
      }
    >
      {/* Overall status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 fade-in">
        <div className="glass-card stat-card-accent p-6">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-xl shrink-0 ${report?.isHealthy ? "bg-[#00ff88]/10 text-[#00ff88]" : "bg-[#ff4757]/10 text-[#ff4757]"}`}>
              {report?.isHealthy ? "✅" : "⚠️"}
            </div>
            <div>
              <p className="text-xl font-bold tracking-tight text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
                {report?.status ?? "Healthy"}
              </p>
              <p className="text-xs text-[#7ba3c8]">Overall platform operational status</p>
            </div>
          </div>
        </div>

        {/* Scanner Sandbox Operational Readiness */}
        <div className="glass-card stat-card-accent p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-xl shrink-0 ${scannerHealth?.readyForScans ? "bg-[#00ff88]/10 text-[#00ff88]" : "bg-[#ff4757]/10 text-[#ff4757]"}`}>
                {scannerHealth?.readyForScans ? "🛡️" : "⚠️"}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <p className="text-xl font-bold tracking-tight text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
                    {scannerHealth?.readyForScans ? "READY FOR SCANS" : "NOT READY FOR SCANS"}
                  </p>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold border ${
                    scannerHealth?.status === "Healthy" ? "badge-healthy" :
                    scannerHealth?.status === "Degraded" ? "badge-degraded" :
                    "badge-unhealthy"
                  }`}>
                    {scannerHealth?.status ?? "Healthy"}
                  </span>
                </div>
                <p className="text-xs text-[#7ba3c8]">
                  Scanner Runtime Sandbox & Egress Boundary
                </p>
              </div>
            </div>
            <span className="badge badge-admin text-[10px]">
              {scannerHealth?.runtime.mode ?? "LocalDocker"}
            </span>
          </div>
        </div>
      </div>

      {/* Scanner Runtime & Egress Gateway Card */}
      {scannerHealth && (
        <div className="glass-card p-6 fade-in space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
                Scanner Runtime Sandbox & Egress Boundary
              </h2>
              <p className="text-xs text-[#7ba3c8]">
                Deterministic security boundary status & resource constraints
              </p>
            </div>
            <span className="text-xs font-mono text-[#00d4ff]">
              {scannerHealth.runtime.version}
            </span>
          </div>

          {/* Diagnostic Callout Messages */}
          {scannerHealth.diagnostics && scannerHealth.diagnostics.length > 0 && (
            <div className={`p-4 rounded-xl border text-xs leading-relaxed ${
              scannerHealth.readyForScans
                ? "bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]"
                : "bg-[#ff4757]/10 border-[#ff4757]/30 text-[#ff4757]"
            }`}>
              <div className="flex items-center gap-2 mb-1 font-bold uppercase tracking-wider">
                <span>{scannerHealth.readyForScans ? "✅" : "⚠️"}</span>
                <span>{scannerHealth.readyForScans ? "Runtime Operational Diagnostics" : "Critical Security Runtime Warning"}</span>
              </div>
              <ul className="list-disc list-inside space-y-1">
                {scannerHealth.diagnostics.map((diag, i) => (
                  <li key={i}>{diag}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            <div className="p-3.5 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10">
              <p className="text-[11px] text-[#4a6580]">
                {scannerHealth.runtime.mode === "CloudManagedContainer" ? "Cloud Service" : "Docker Daemon"}
              </p>
              <div className="flex items-center gap-2 mt-1">
                <div className={`w-2 h-2 rounded-full ${scannerHealth.runtime.available ? "bg-[#00ff88]" : "bg-[#ff4757]"}`} />
                <span className="text-xs font-bold text-[#e8f4ff]">{scannerHealth.runtime.available ? "AVAILABLE" : "OFFLINE"}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10">
              <p className="text-[11px] text-[#4a6580]">Image Provenance</p>
              <div className="flex items-center gap-2 mt-1">
                <div className={`w-2 h-2 rounded-full ${scannerHealth.provenance.imageDigestRequired ? "bg-[#00ff88]" : "bg-[#ffa502]"}`} />
                <span className="text-xs font-bold text-[#e8f4ff]">{scannerHealth.provenance.imageDigestRequired ? "ENFORCED" : "OPTIONAL"}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10">
              <p className="text-[11px] text-[#4a6580]">Egress Gateway</p>
              <div className="flex items-center gap-2 mt-1">
                <div className={`w-2 h-2 rounded-full ${scannerHealth.egress.gatewayHealthy ? "bg-[#00ff88]" : "bg-[#ff4757]"}`} />
                <span className="text-xs font-bold text-[#e8f4ff]">{scannerHealth.egress.gatewayHealthy ? "ENFORCED" : "OFFLINE"}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10">
              <p className="text-[11px] text-[#4a6580]">Sandbox Isolation</p>
              <div className="flex items-center gap-2 mt-1">
                <div className={`w-2 h-2 rounded-full ${scannerHealth.sandbox?.sandboxIsolated !== false ? "bg-[#00d4ff]" : "bg-[#ff4757]"}`} />
                <span className="text-xs font-bold text-[#e8f4ff]">{scannerHealth.sandbox?.sandboxIsolated !== false ? "ISOLATED" : "UNSAFE"}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10">
              <p className="text-[11px] text-[#4a6580]">Active Scan Jobs</p>
              <p className="text-xs font-bold text-[#00d4ff] mt-1">{scannerHealth.activeJobsCount} Active</p>
            </div>
          </div>

          {/* Sandbox Resource Limits */}
          <div className="pt-4 border-t border-[#00d4ff]/10">
            <p className="text-[11px] font-semibold text-[#4a6580] uppercase tracking-wider mb-3">
              SANDBOX ENFORCEMENT LIMITS
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
              <div className="p-3 rounded-xl bg-[#080c14] border border-[#00d4ff]/10">
                <p className="text-[10px] text-[#7ba3c8]">CPU Limit</p>
                <p className="text-xs font-bold font-mono text-[#e8f4ff]">{scannerHealth.limits.cpuCores} Cores</p>
              </div>
              <div className="p-3 rounded-xl bg-[#080c14] border border-[#00d4ff]/10">
                <p className="text-[10px] text-[#7ba3c8]">Memory Limit</p>
                <p className="text-xs font-bold font-mono text-[#e8f4ff]">{(scannerHealth.limits.memoryBytes / (1024 * 1024 * 1024)).toFixed(1)} GB</p>
              </div>
              <div className="p-3 rounded-xl bg-[#080c14] border border-[#00d4ff]/10">
                <p className="text-[10px] text-[#7ba3c8]">PID Limit</p>
                <p className="text-xs font-bold font-mono text-[#e8f4ff]">{scannerHealth.limits.pids} PIDs</p>
              </div>
              <div className="p-3 rounded-xl bg-[#080c14] border border-[#00d4ff]/10">
                <p className="text-[10px] text-[#7ba3c8]">Scratch Disk</p>
                <p className="text-xs font-bold font-mono text-[#e8f4ff]">{(scannerHealth.limits.scratchBytes / (1024 * 1024)).toFixed(0)} MB</p>
              </div>
              <div className="p-3 rounded-xl bg-[#080c14] border border-[#00d4ff]/10">
                <p className="text-[10px] text-[#7ba3c8]">Timeout</p>
                <p className="text-xs font-bold font-mono text-[#e8f4ff]">{scannerHealth.limits.timeoutSeconds}s</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Components (Admin only) */}
      {user.isPlatformAdmin && report?.components && report.components.length > 0 && (
        <div className="glass-card p-6 fade-in space-y-4">
          <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            Microservice & Component Health Breakdown
          </h2>
          <div className="space-y-2">
            {report.components.map((comp, i) => (
              <div key={i} className="flex items-center justify-between p-3.5 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10">
                <div className="flex items-center gap-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${comp.isHealthy ? "bg-[#00ff88]" : "bg-[#ff4757]"}`} />
                  <div>
                    <p className="font-bold text-xs text-[#e8f4ff]">{comp.name}</p>
                    {comp.detail && <p className="text-[11px] text-[#7ba3c8]">{comp.detail}</p>}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {comp.latencyMs !== undefined && (
                    <p className="text-xs font-mono text-[#00d4ff]">
                      {comp.latencyMs.toFixed(1)}ms
                    </p>
                  )}
                  <span className={`px-2.5 py-1 text-[10px] font-semibold rounded-full border ${
                    comp.isHealthy ? "badge-healthy" : "badge-unhealthy"
                  }`}>
                    {comp.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </AppLayout>
  );
}

