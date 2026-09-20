"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
import { apiFetch, getErrorMessage } from "@/lib/api-client";

interface HealthOverview {
  systemHealth: "Healthy" | "Warning" | "Degraded";
  activeIncidents: number;
  criticalIncidents: number;
  pendingJobs: number;
  runningJobs: number;
  overdueCampaigns: number;
  evaluatedAtUtc: string;
}

interface AiDiagnosis {
  id: string;
  incidentId: string;
  analyzedAtUtc: string;
  providerUsed: string;
  rootCauseSummary: string;
  suggestedRemediation: string;
  confidenceScore: number;
  isDeterministicFallback: boolean;
  sanitizedPrompt: string;
}

interface OperationalIncident {
  id: string;
  tenantId?: string;
  severity: number; // 0: Info, 1: Low, 2: Medium, 3: High, 4: Critical
  category: number; // 0: WorkerHeartbeatLost, 1: LeaseDeadlock, 2: DatabaseDegraded, 3: CampaignStall, 4: AiProviderQuotaExhausted, 5: ConsecutiveJobFailures
  status: number; // 0: Detected, 1: Investigating, 2: Mitigated, 3: Resolved, 4: Suppressed
  title: string;
  fingerprint: string;
  firstObservedAtUtc: string;
  lastObservedAtUtc: string;
  occurrenceCount: number;
  detailsJson?: string;
  resolutionNotes?: string;
  mitigationActionTaken?: string;
  aiDiagnosisId?: string;
  aiDiagnosis?: AiDiagnosis;
}

const SEVERITY_NAMES = ["Info", "Low", "Medium", "High", "Critical"];
const CATEGORY_NAMES = [
  "Worker Heartbeat Lost",
  "Lease Deadlock",
  "Database Degraded",
  "Campaign Stall",
  "AI Quota Exhausted",
  "Consecutive Failures"
];
const STATUS_NAMES = ["Detected", "Investigating", "Mitigated", "Resolved", "Suppressed"];

export default function OperationsPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; userId: string; email?: string } | null>(null);
  const [overview, setOverview] = useState<HealthOverview | null>(null);
  const [incidents, setIncidents] = useState<OperationalIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ACTIVE");
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Modals
  const [selectedIncident, setSelectedIncident] = useState<OperationalIncident | null>(null);
  const [diagnosing, setDiagnosing] = useState(false);
  const [activeDiagnosis, setActiveDiagnosis] = useState<AiDiagnosis | null>(null);

  const [resolveIncidentId, setResolveIncidentId] = useState<string | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState("");
  const [resolving, setResolving] = useState(false);

  const loadData = useCallback(async (isInitial = false) => {
    try {
      if (!isInitial) setRefreshing(true);
      const [overviewRes, incidentsRes] = await Promise.all([
        apiFetch("/api/v1/operations/health-overview"),
        apiFetch("/api/v1/operations/incidents?pageSize=100")
      ]);

      if (overviewRes.ok) {
        setOverview(await overviewRes.json());
      }
      if (incidentsRes.ok) {
        const incData = await incidentsRes.json();
        setIncidents(incData.items || []);
      }
      setError(null);
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Failed to load operational data."));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  // Auth verification and initial data load
  useEffect(() => {
    async function init() {
      try {
        const res = await apiFetch("/api/v1/auth/me");
        if (res.ok) {
          const userData = await res.json();
          setUser(userData);
          if (!userData.isPlatformAdmin) {
            router.push("/dashboard");
          } else {
            await loadData(true);
          }
        } else {
          router.push("/login");
        }
      } catch {
        router.push("/login");
      }
    }
    init();
  }, [router, loadData]);

  // Auto-refresh interval (15 seconds)
  useEffect(() => {
    if (!autoRefresh || !user?.isPlatformAdmin) return;
    const interval = setInterval(() => {
      loadData();
    }, 15000);
    return () => clearInterval(interval);
  }, [autoRefresh, user, loadData]);

  const triggerCycle = async () => {
    try {
      setRefreshing(true);
      const res = await apiFetch("/api/v1/operations/cycle", { method: "POST" });
      if (res.ok) {
        setActionSuccess("Autonomous detection cycle completed.");
        await loadData();
      } else {
        setError("Failed to run detection cycle.");
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Cycle error"));
    } finally {
      setRefreshing(false);
    }
  };

  const handleDiagnose = async (incident: OperationalIncident) => {
    setSelectedIncident(incident);
    setActiveDiagnosis(incident.aiDiagnosis || null);

    if (!incident.aiDiagnosis) {
      try {
        setDiagnosing(true);
        const res = await apiFetch(`/api/v1/operations/incidents/${incident.id}/diagnose`, { method: "POST" });
        if (res.ok) {
          const diag: AiDiagnosis = await res.json();
          setActiveDiagnosis(diag);
          // update local state
          setIncidents((prev) =>
            prev.map((i) => (i.id === incident.id ? { ...i, aiDiagnosis: diag, status: 1 } : i))
          );
        } else {
          setError("AI diagnosis failed to return result.");
        }
      } catch (err: unknown) {
        setError(getErrorMessage(err, "Error triggering AI diagnosis."));
      } finally {
        setDiagnosing(false);
      }
    }
  };

  const handleMitigate = async (incidentId: string) => {
    try {
      const res = await apiFetch(`/api/v1/operations/incidents/${incidentId}/mitigate`, {
        method: "POST",
        body: JSON.stringify({ notes: "Triggered from Operations AI Console" }),
        headers: { "Content-Type": "application/json" }
      });
      if (res.ok) {
        setActionSuccess("Mitigation applied successfully.");
        await loadData();
        if (selectedIncident?.id === incidentId) {
          setSelectedIncident(null);
        }
      } else {
        setError("Failed to apply mitigation.");
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Mitigation failed."));
    }
  };

  const handleResolve = async () => {
    if (!resolveIncidentId || !resolutionNotes.trim()) return;
    try {
      setResolving(true);
      const res = await apiFetch(`/api/v1/operations/incidents/${resolveIncidentId}/resolve`, {
        method: "POST",
        body: JSON.stringify({ notes: resolutionNotes }),
        headers: { "Content-Type": "application/json" }
      });
      if (res.ok) {
        setActionSuccess("Incident resolved.");
        setResolveIncidentId(null);
        setResolutionNotes("");
        await loadData();
      } else {
        setError("Failed to resolve incident.");
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Resolution failed."));
    } finally {
      setResolving(false);
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    if (severityFilter !== "ALL" && SEVERITY_NAMES[inc.severity] !== severityFilter) {
      return false;
    }
    if (statusFilter === "ACTIVE" && (inc.status === 3 || inc.status === 4)) {
      return false;
    }
    if (statusFilter !== "ALL" && statusFilter !== "ACTIVE" && STATUS_NAMES[inc.status] !== statusFilter) {
      return false;
    }
    return true;
  });

  const getSeverityBadgeClass = (severity: number) => {
    switch (severity) {
      case 4: // Critical
        return "badge-unhealthy animate-pulse";
      case 3: // High
        return "badge-degraded";
      case 2: // Medium
        return "badge-degraded";
      default:
        return "badge-admin";
    }
  };

  const getStatusBadgeClass = (status: number) => {
    switch (status) {
      case 0: // Detected
        return "badge-unhealthy";
      case 1: // Investigating
        return "badge-admin";
      case 2: // Mitigated
        return "badge-healthy";
      case 3: // Resolved
        return "badge-healthy line-through opacity-60";
      default:
        return "badge-admin";
    }
  };

  if (loading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-[#7ba3c8] font-medium">Loading Operations AI Engine…</p>
        </div>
      </div>
    );
  }

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="Operations AI & Fleet Health"
      subtitle="Autonomous incident detection, worker lease recovery & multi-LLM root-cause diagnosis"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-xs text-[#7ba3c8] bg-white/5 px-3 py-1.5 rounded-lg border border-white/10 cursor-pointer font-medium">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded bg-[#080c14] border-[#00d4ff]/30 text-[#00d4ff] focus:ring-0"
            />
            <span>Live Pulse (15s)</span>
          </label>

          <button
            onClick={() => loadData()}
            disabled={refreshing}
            className="btn-secondary text-xs"
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>

          <button
            onClick={triggerCycle}
            disabled={refreshing}
            className="btn-primary text-xs flex items-center gap-1.5"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
            </svg>
            <span>Trigger Detection Cycle</span>
          </button>
        </div>
      }
    >
      {/* Status Alerts */}
      {error && (
        <div className="p-4 rounded-xl border border-[#ff4757]/30 bg-[#ff4757]/10 text-[#ff4757] text-xs font-semibold flex items-center justify-between fade-in">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="hover:underline font-bold">✕</button>
        </div>
      )}
      {actionSuccess && (
        <div className="p-4 rounded-xl border border-[#00ff88]/30 bg-[#00ff88]/10 text-[#00ff88] text-xs font-semibold flex items-center justify-between fade-in">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="hover:underline font-bold">✕</button>
        </div>
      )}

      {/* Health Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 fade-in">
        <div className="glass-card p-5">
          <div className="flex items-center justify-between text-xs text-[#4a6580] font-semibold uppercase tracking-wider mb-2">
            <span>Overall Fleet Health</span>
            <span className={`w-2.5 h-2.5 rounded-full ${overview?.systemHealth === "Healthy" ? "bg-[#00ff88]" : overview?.systemHealth === "Warning" ? "bg-[#ffa502]" : "bg-[#ff4757] animate-ping"}`} />
          </div>
          <div className="text-2xl font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            {overview?.systemHealth || "Healthy"}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">Autonomous self-healing active</p>
        </div>

        <div className="glass-card p-5">
          <div className="flex items-center justify-between text-xs text-[#4a6580] font-semibold uppercase tracking-wider mb-2">
            <span>Active Incidents</span>
            <span className="text-[#ff4757] font-semibold">{overview?.criticalIncidents || 0} Critical</span>
          </div>
          <div className="text-2xl font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            {overview?.activeIncidents ?? 0}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">Requiring triage or mitigation</p>
        </div>

        <div className="glass-card p-5">
          <div className="flex items-center justify-between text-xs text-[#4a6580] font-semibold uppercase tracking-wider mb-2">
            <span>Security Scan Queue</span>
            <span className="text-[#00d4ff] font-semibold">{overview?.runningJobs || 0} Running</span>
          </div>
          <div className="text-2xl font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            {overview?.pendingJobs ?? 0}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">Pending claims in PostgreSQL queue</p>
        </div>

        <div className="glass-card p-5">
          <div className="flex items-center justify-between text-xs text-[#4a6580] font-semibold uppercase tracking-wider mb-2">
            <span>Campaign Scheduler</span>
            <span className="text-[#ffa502] font-semibold">Overdue</span>
          </div>
          <div className="text-2xl font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            {overview?.overdueCampaigns ?? 0}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">Overdue continuous campaigns</p>
        </div>
      </div>

      {/* Main Incidents Table Section */}
      <div className="space-y-4 fade-in">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
              Operational Incident Log
            </h2>
            <p className="text-xs text-[#7ba3c8]">
              Live operational events, worker stalls & continuous recovery history
            </p>
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="flex items-center gap-1 bg-white/5 p-1 rounded-xl border border-white/10">
              {["ACTIVE", "ALL", "Detected", "Mitigated", "Resolved"].map((status) => (
                <button
                  key={status}
                  onClick={() => setStatusFilter(status)}
                  className={`px-2.5 py-1 rounded-lg transition text-xs font-semibold ${
                    statusFilter === status
                      ? "bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/40 shadow-sm"
                      : "text-[#7ba3c8] hover:text-white"
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-[#080c14] border border-[#00d4ff]/20 rounded-xl px-3 py-1.5 text-xs text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        {/* Table Container */}
        <div className="glass-card overflow-hidden">
          {filteredIncidents.length === 0 ? (
            <div className="py-16 text-center text-[#7ba3c8] space-y-2">
              <svg className="w-10 h-10 mx-auto text-[#4a6580]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
              <p className="text-sm font-semibold text-[#e8f4ff]">Zero active operational incidents</p>
              <p className="text-xs">All worker fleet heartbeats and scan queues are nominal.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse min-w-[800px]">
                <thead>
                  <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                    <th className="p-4">Severity</th>
                    <th className="p-4">Incident Title & Category</th>
                    <th className="p-4">Status</th>
                    <th className="p-4">Occurrences</th>
                    <th className="p-4">Last Observed</th>
                    <th className="p-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
                  {filteredIncidents.map((incident) => (
                    <tr key={incident.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="p-4">
                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${getSeverityBadgeClass(incident.severity)}`}>
                          {SEVERITY_NAMES[incident.severity]}
                        </span>
                      </td>

                      <td className="p-4 max-w-md">
                        <div className="font-bold text-[#e8f4ff] truncate">{incident.title}</div>
                        <div className="text-[11px] text-[#7ba3c8] flex items-center gap-2 mt-0.5">
                          <span className="text-[#00d4ff] font-medium">{CATEGORY_NAMES[incident.category]}</span>
                          <span>•</span>
                          <span className="font-mono text-[#4a6580] truncate">{incident.fingerprint}</span>
                        </div>
                        {incident.mitigationActionTaken && (
                          <div className="text-[11px] text-[#00ff88] mt-1 flex items-center gap-1 font-medium">
                            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12" /></svg>
                            <span>{incident.mitigationActionTaken}</span>
                          </div>
                        )}
                      </td>

                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${getStatusBadgeClass(incident.status)}`}>
                          {STATUS_NAMES[incident.status]}
                        </span>
                      </td>

                      <td className="p-4 text-[#7ba3c8] font-mono">
                        {incident.occurrenceCount}x
                      </td>

                      <td className="p-4 text-[#7ba3c8] text-[11px]">
                        {new Date(incident.lastObservedAtUtc).toLocaleTimeString()}
                      </td>

                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleDiagnose(incident)}
                            className="btn-primary text-[11px] py-1 px-2.5 flex items-center gap-1"
                          >
                            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" /></svg>
                            <span>AI Diagnose</span>
                          </button>

                          {incident.status !== 2 && incident.status !== 3 && (
                            <button
                              onClick={() => handleMitigate(incident.id)}
                              className="btn-secondary text-[11px] py-1 px-2.5"
                            >
                              Mitigate
                            </button>
                          )}

                          {incident.status !== 3 && (
                            <button
                              onClick={() => {
                                setResolveIncidentId(incident.id);
                                setResolutionNotes("");
                              }}
                              className="btn-secondary text-[11px] py-1 px-2.5"
                            >
                              Resolve
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* AI Diagnosis Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 fade-in">
          <div className="glass-card max-w-2xl w-full p-6 border-[#00d4ff]/30 relative space-y-4">
            <button
              onClick={() => setSelectedIncident(null)}
              className="absolute top-4 right-4 text-[#7ba3c8] hover:text-white text-lg font-bold"
            >
              ✕
            </button>

            <div className="flex items-center space-x-2 text-[#00d4ff] text-xs font-semibold uppercase tracking-wider">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" /><circle cx="12" cy="12" r="3" /></svg>
              <span>AI Operational Diagnostic Report</span>
            </div>

            <h3 className="text-lg font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>{selectedIncident.title}</h3>
            <p className="text-xs text-[#7ba3c8]">
              Fingerprint: <span className="font-mono text-[#4a6580]">{selectedIncident.fingerprint}</span>
            </p>

            {diagnosing ? (
              <div className="py-12 flex flex-col items-center justify-center space-y-3">
                <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
                <p className="text-xs text-[#7ba3c8]">Sanitizing execution trace and running AI diagnosis...</p>
              </div>
            ) : activeDiagnosis ? (
              <div className="space-y-4 pt-2">
                <div className="flex items-center justify-between text-xs p-3.5 rounded-xl bg-[#080c14] border border-[#00d4ff]/10">
                  <div>
                    <span className="text-[#7ba3c8]">Provider: </span>
                    <span className="text-[#e8f4ff] font-semibold">{activeDiagnosis.providerUsed}</span>
                    {activeDiagnosis.isDeterministicFallback && (
                      <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-[#ffa502]/20 text-[#ffa502] rounded font-semibold">Fallback</span>
                    )}
                  </div>
                  <div>
                    <span className="text-[#7ba3c8]">Confidence: </span>
                    <span className="text-[#00ff88] font-bold">
                      {Math.round(activeDiagnosis.confidenceScore * 100)}%
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#080c14]/80 border border-[#ff4757]/30 space-y-1">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-[#ff4757]">Identified Root Cause</h4>
                  <p className="text-xs text-[#e8f4ff] leading-relaxed">{activeDiagnosis.rootCauseSummary}</p>
                </div>

                <div className="p-4 rounded-xl bg-[#080c14]/80 border border-[#00ff88]/30 space-y-1">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-[#00ff88]">Recommended Mitigation</h4>
                  <p className="text-xs text-[#e8f4ff] leading-relaxed">{activeDiagnosis.suggestedRemediation}</p>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    onClick={() => handleMitigate(selectedIncident.id)}
                    className="btn-primary text-xs"
                  >
                    Execute Recommended Mitigation
                  </button>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-xs text-[#7ba3c8]">
                Diagnosis could not be generated.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Resolve Incident Dialog */}
      {resolveIncidentId && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 fade-in">
          <div className="glass-card max-w-md w-full p-6 border-[#00d4ff]/30 space-y-4">
            <h3 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>Resolve Operational Incident</h3>
            <p className="text-xs text-[#7ba3c8]">
              Record the root cause fix or operator notes before marking this incident as resolved.
            </p>

            <textarea
              value={resolutionNotes}
              onChange={(e) => setResolutionNotes(e.target.value)}
              placeholder="e.g. Host restarted, worker leases cleanly cleared, memory leak patched."
              rows={3}
              className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-3 text-xs text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
            />

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setResolveIncidentId(null)}
                className="btn-secondary text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleResolve}
                disabled={resolving || !resolutionNotes.trim()}
                className="btn-primary text-xs"
              >
                {resolving ? "Resolving..." : "Confirm Resolution"}
              </button>
            </div>
          </div>
        </div>
      )}
    </AppLayout>
  );
}

