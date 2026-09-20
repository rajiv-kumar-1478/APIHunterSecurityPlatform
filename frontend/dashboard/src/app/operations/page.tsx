"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";
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
        return "bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse";
      case 3: // High
        return "bg-amber-500/20 text-amber-400 border border-amber-500/30";
      case 2: // Medium
        return "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30";
      default:
        return "bg-slate-700/50 text-slate-300 border border-slate-600";
    }
  };

  const getStatusBadgeClass = (status: number) => {
    switch (status) {
      case 0: // Detected
        return "bg-rose-900/40 text-rose-300";
      case 1: // Investigating
        return "bg-blue-900/40 text-blue-300";
      case 2: // Mitigated
        return "bg-emerald-900/40 text-emerald-300";
      case 3: // Resolved
        return "bg-slate-800 text-slate-400 line-through";
      default:
        return "bg-slate-800 text-slate-400";
    }
  };

  if (loading || !user) {
    return (
      <div className="flex h-screen bg-slate-950 text-slate-100">
        <Sidebar isAdmin={user?.isPlatformAdmin ?? false} userEmail={user?.email} />
        <div className="flex-1 flex items-center justify-center">
          <div className="flex items-center space-x-3 text-slate-400">
            <div className="w-5 h-5 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
            <span>Loading Operations AI Console...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      <Sidebar isAdmin={user?.isPlatformAdmin ?? false} userEmail={user?.email} />

      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Header Bar */}
        <header className="px-8 py-6 border-b border-slate-800/80 bg-slate-900/40 backdrop-blur sticky top-0 z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                <svg className="w-6 h-6 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                Operations AI & Fleet Health
              </h1>
              <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                Phase 10 Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Autonomous incident detection, lease recovery, and AI-assisted root-cause diagnosis.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <label className="flex items-center space-x-2 text-xs text-slate-300 bg-slate-800/60 px-3 py-1.5 rounded-lg border border-slate-700/60 cursor-pointer">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded border-slate-700 text-indigo-500 focus:ring-indigo-400"
              />
              <span>Live Pulse (15s)</span>
            </label>

            <button
              onClick={() => loadData()}
              disabled={refreshing}
              className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition"
            >
              {refreshing ? "Refreshing..." : "Refresh"}
            </button>

            <button
              onClick={triggerCycle}
              disabled={refreshing}
              className="px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg shadow-sm shadow-indigo-500/20 transition flex items-center space-x-1.5"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
              </svg>
              <span>Trigger Detection Cycle</span>
            </button>
          </div>
        </header>

        {/* Status Alerts */}
        {error && (
          <div className="mx-8 mt-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="text-rose-400 hover:text-white font-bold ml-4">✕</button>
          </div>
        )}
        {actionSuccess && (
          <div className="mx-8 mt-6 p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-sm flex items-center justify-between">
            <span>{actionSuccess}</span>
            <button onClick={() => setActionSuccess(null)} className="text-emerald-400 hover:text-white font-bold ml-4">✕</button>
          </div>
        )}

        {/* Health Metric Cards */}
        <div className="px-8 mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Overall Platform Health</span>
              <span className={`w-2.5 h-2.5 rounded-full ${overview?.systemHealth === "Healthy" ? "bg-emerald-400" : overview?.systemHealth === "Warning" ? "bg-amber-400" : "bg-rose-500 animate-ping"}`} />
            </div>
            <div className="mt-3">
              <span className={`text-2xl font-bold tracking-tight ${overview?.systemHealth === "Healthy" ? "text-emerald-400" : overview?.systemHealth === "Warning" ? "text-amber-400" : "text-rose-400"}`}>
                {overview?.systemHealth || "Unknown"}
              </span>
              <p className="text-xs text-slate-500 mt-1">Autonomous self-healing engine active</p>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Active Incidents</span>
              <span className="text-rose-400 font-semibold">{overview?.criticalIncidents || 0} Critical</span>
            </div>
            <div className="mt-3">
              <span className="text-2xl font-bold tracking-tight text-white">
                {overview?.activeIncidents ?? 0}
              </span>
              <p className="text-xs text-slate-500 mt-1">Requiring triage or mitigation</p>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Security Scan Queue</span>
              <span className="text-indigo-400 font-semibold">{overview?.runningJobs || 0} Running</span>
            </div>
            <div className="mt-3">
              <span className="text-2xl font-bold tracking-tight text-white">
                {overview?.pendingJobs ?? 0}
              </span>
              <p className="text-xs text-slate-500 mt-1">Pending claims in PostgreSQL queue</p>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Campaign Scheduler</span>
              <span className="text-amber-400 font-semibold">Overdue</span>
            </div>
            <div className="mt-3">
              <span className="text-2xl font-bold tracking-tight text-white">
                {overview?.overdueCampaigns ?? 0}
              </span>
              <p className="text-xs text-slate-500 mt-1">Overdue continuous scan campaigns</p>
            </div>
          </div>
        </div>

        {/* Main Incidents Table Section */}
        <div className="px-8 mt-8 pb-12">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
            <div>
              <h2 className="text-lg font-bold text-white">Operational Incident Log</h2>
              <p className="text-xs text-slate-400">
                Live operational events, worker stalls, and continuous recovery history.
              </p>
            </div>

            {/* Filter Pills */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="flex items-center space-x-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800">
                {["ACTIVE", "ALL", "Detected", "Mitigated", "Resolved"].map((status) => (
                  <button
                    key={status}
                    onClick={() => setStatusFilter(status)}
                    className={`px-2.5 py-1 rounded-lg transition font-medium ${
                      statusFilter === status
                        ? "bg-indigo-600 text-white shadow-sm"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {status}
                  </button>
                ))}
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:ring-1 focus:ring-indigo-500"
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
          <div className="rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur overflow-hidden shadow-sm">
            {filteredIncidents.length === 0 ? (
              <div className="py-16 text-center text-slate-500">
                <svg className="w-12 h-12 mx-auto text-slate-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                  <polyline points="22 4 12 14.01 9 11.01" />
                </svg>
                <p className="text-sm font-medium text-slate-400">Zero active operational incidents</p>
                <p className="text-xs text-slate-600 mt-1">All worker fleet heartbeats and scan queues are nominal.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-800/40 text-slate-400 uppercase tracking-wider text-[10px] font-semibold border-b border-slate-800">
                    <tr>
                      <th className="px-5 py-3">Severity</th>
                      <th className="px-5 py-3">Incident Title & Category</th>
                      <th className="px-5 py-3">Status</th>
                      <th className="px-5 py-3">Occurrences</th>
                      <th className="px-5 py-3">Last Observed</th>
                      <th className="px-5 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredIncidents.map((incident) => (
                      <tr key={incident.id} className="hover:bg-slate-800/30 transition">
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${getSeverityBadgeClass(incident.severity)}`}>
                            {SEVERITY_NAMES[incident.severity]}
                          </span>
                        </td>

                        <td className="px-5 py-3.5 max-w-md font-sans">
                          <div className="font-semibold text-slate-100 truncate">{incident.title}</div>
                          <div className="text-[11px] text-slate-500 flex items-center gap-2 mt-0.5">
                            <span className="text-indigo-400">{CATEGORY_NAMES[incident.category]}</span>
                            <span>•</span>
                            <span className="font-mono text-slate-600 truncate">{incident.fingerprint}</span>
                          </div>
                          {incident.mitigationActionTaken && (
                            <div className="text-[11px] text-emerald-400/90 mt-1 flex items-center gap-1 font-sans">
                              <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12" /></svg>
                              <span>{incident.mitigationActionTaken}</span>
                            </div>
                          )}
                        </td>

                        <td className="px-5 py-3.5 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${getStatusBadgeClass(incident.status)}`}>
                            {STATUS_NAMES[incident.status]}
                          </span>
                        </td>

                        <td className="px-5 py-3.5 whitespace-nowrap text-slate-400">
                          {incident.occurrenceCount}x
                        </td>

                        <td className="px-5 py-3.5 whitespace-nowrap text-slate-400 text-[11px]">
                          {new Date(incident.lastObservedAtUtc).toLocaleTimeString()}
                        </td>

                        <td className="px-5 py-3.5 whitespace-nowrap text-right space-x-2 font-sans">
                          <button
                            onClick={() => handleDiagnose(incident)}
                            className="px-2.5 py-1 text-xs font-medium rounded-lg bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 border border-indigo-500/30 transition inline-flex items-center space-x-1"
                          >
                            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" /></svg>
                            <span>AI Diagnose</span>
                          </button>

                          {incident.status !== 2 && incident.status !== 3 && (
                            <button
                              onClick={() => handleMitigate(incident.id)}
                              className="px-2.5 py-1 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 transition"
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
                              className="px-2.5 py-1 text-xs font-medium rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
                            >
                              Resolve
                            </button>
                          )}
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
          <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative">
              <button
                onClick={() => setSelectedIncident(null)}
                className="absolute top-4 right-4 text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>

              <div className="flex items-center space-x-2 text-indigo-400 text-xs font-semibold uppercase tracking-wider mb-2">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" /><circle cx="12" cy="12" r="3" /></svg>
                <span>AI Operational Diagnostic Report</span>
              </div>

              <h3 className="text-lg font-bold text-white">{selectedIncident.title}</h3>
              <p className="text-xs text-slate-400 mt-1">
                Fingerprint: <span className="font-mono text-slate-500">{selectedIncident.fingerprint}</span>
              </p>

              {diagnosing ? (
                <div className="py-12 flex flex-col items-center justify-center space-y-3">
                  <div className="w-8 h-8 border-3 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                  <p className="text-xs text-slate-400">Sanitizing execution trace and running AI diagnosis...</p>
                </div>
              ) : activeDiagnosis ? (
                <div className="mt-5 space-y-4">
                  <div className="flex items-center justify-between text-xs bg-slate-800/40 p-3 rounded-xl border border-slate-800">
                    <div>
                      <span className="text-slate-400">Provider: </span>
                      <span className="text-slate-200 font-semibold">{activeDiagnosis.providerUsed}</span>
                      {activeDiagnosis.isDeterministicFallback && (
                        <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-amber-500/20 text-amber-300 rounded">Fallback</span>
                      )}
                    </div>
                    <div>
                      <span className="text-slate-400">Confidence: </span>
                      <span className="text-emerald-400 font-bold">
                        {Math.round(activeDiagnosis.confidenceScore * 100)}%
                      </span>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-800/30 border border-slate-800">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-rose-400 mb-1.5">Identified Root Cause</h4>
                    <p className="text-sm text-slate-200 leading-relaxed">{activeDiagnosis.rootCauseSummary}</p>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-800/30 border border-slate-800">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 mb-1.5">Recommended Mitigation</h4>
                    <p className="text-sm text-slate-200 leading-relaxed">{activeDiagnosis.suggestedRemediation}</p>
                  </div>

                  <div className="pt-2 flex justify-end space-x-3">
                    <button
                      onClick={() => handleMitigate(selectedIncident.id)}
                      className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-xl transition shadow-sm"
                    >
                      Execute Recommended Mitigation
                    </button>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-slate-500">
                  Diagnosis could not be generated.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Resolve Incident Dialog */}
        {resolveIncidentId && (
          <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl">
              <h3 className="text-base font-bold text-white mb-2">Resolve Operational Incident</h3>
              <p className="text-xs text-slate-400 mb-4">
                Record the root cause fix or operator notes before marking this incident as resolved.
              </p>

              <textarea
                value={resolutionNotes}
                onChange={(e) => setResolutionNotes(e.target.value)}
                placeholder="e.g. Host restarted, worker leases cleanly cleared, memory leak patched."
                rows={3}
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />

              <div className="mt-4 flex justify-end space-x-2 text-xs">
                <button
                  onClick={() => setResolveIncidentId(null)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  onClick={handleResolve}
                  disabled={resolving || !resolutionNotes.trim()}
                  className="px-4 py-1.5 rounded-lg bg-emerald-600 text-white font-medium hover:bg-emerald-500 disabled:opacity-50"
                >
                  {resolving ? "Resolving..." : "Confirm Resolution"}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
