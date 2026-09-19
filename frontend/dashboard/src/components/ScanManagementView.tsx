"use client";

import { useEffect, useState, useCallback } from "react";
import {
  ScanJobDetailDto,
  ScanExecutionReceiptDto,
  ScanCampaignDto,
  CampaignOperationalHealthDto,
  getScanJobs,
  getScanJobReceipt,
  createScanJob,
  retryScanJob,
  cancelScanJob,
  getCampaigns,
  getCampaignHealth,
  pauseCampaign,
  resumeCampaign,
  triggerCampaignRunNow,
} from "@/lib/security-api";
import { CampaignHealthCard } from "./campaigns/CampaignHealthCard";
import { CampaignHistoryDrawer } from "./campaigns/CampaignHistoryDrawer";
import { CampaignDiagnosticsModal } from "./campaigns/CampaignDiagnosticsModal";

export function ScanManagementView() {
  const [activeTab, setActiveTab] = useState<"jobs" | "campaigns">("jobs");

  // Scan Jobs State
  const [jobs, setJobs] = useState<ScanJobDetailDto[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [selectedReceipt, setSelectedReceipt] = useState<ScanExecutionReceiptDto | null>(null);
  const [inspectingJob, setInspectingJob] = useState<ScanJobDetailDto | null>(null);
  const [receiptLoading, setReceiptLoading] = useState<boolean>(false);

  // Campaigns Observability State
  const [campaigns, setCampaigns] = useState<ScanCampaignDto[]>([]);
  const [campaignHealth, setCampaignHealth] = useState<CampaignOperationalHealthDto | null>(null);
  const [campaignsLoading, setCampaignsLoading] = useState<boolean>(true);
  const [selectedCampaignForHistory, setSelectedCampaignForHistory] = useState<ScanCampaignDto | null>(null);
  const [selectedCampaignForDiag, setSelectedCampaignForDiag] = useState<ScanCampaignDto | null>(null);
  const [campaignActionRunning, setCampaignActionRunning] = useState<string | null>(null);

  // New Scan Modal State
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [targetUrl, setTargetUrl] = useState<string>("");
  const [scanProfile, setScanProfile] = useState<number>(1); // Standard default
  const [creating, setCreating] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Load Scan Jobs
  const loadJobs = useCallback(async () => {
    setLoading(true);
    const data = await getScanJobs(statusFilter || undefined);
    setJobs(data);
    setLoading(false);
  }, [statusFilter]);

  // Load Continuous Campaigns
  const loadCampaigns = useCallback(async () => {
    setCampaignsLoading(true);
    const [cData, hData] = await Promise.all([getCampaigns(), getCampaignHealth()]);
    setCampaigns(cData);
    setCampaignHealth(hData);
    setCampaignsLoading(false);
  }, []);

  useEffect(() => {
    let cancelled = false;

    if (activeTab === "jobs") {
      void getScanJobs(statusFilter || undefined).then((data) => {
        if (cancelled) return;
        setJobs(data);
        setLoading(false);
      });

      const interval = setInterval(() => {
        if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
        void loadJobs();
      }, 5000);
      return () => {
        cancelled = true;
        clearInterval(interval);
      };
    }

    void Promise.all([getCampaigns(), getCampaignHealth()]).then(([campaignData, healthData]) => {
      if (cancelled) return;
      setCampaigns(campaignData);
      setCampaignHealth(healthData);
      setCampaignsLoading(false);
    });

    // Modest 15-second polling with visibility pause
    const interval = setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      void loadCampaigns();
    }, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeTab, loadJobs, loadCampaigns, statusFilter]);

  // Inspect Receipt
  const handleInspectReceipt = async (job: ScanJobDetailDto) => {
    setInspectingJob(job);
    if (job.executionReceipt) {
      setSelectedReceipt(job.executionReceipt);
    } else {
      setReceiptLoading(true);
      const receipt = await getScanJobReceipt(job.id);
      setSelectedReceipt(receipt);
      setReceiptLoading(false);
    }
  };

  // Retry Job
  const handleRetry = async (jobId: string) => {
    const res = await retryScanJob(jobId);
    if (res.success) {
      loadJobs();
    } else {
      alert(res.message ?? "Retry failed.");
    }
  };

  // Cancel Job
  const handleCancel = async (job: ScanJobDetailDto) => {
    const reason = prompt("Enter cancellation reason:", "Operator cancelled scan");
    if (!reason) return;

    const res = await cancelScanJob(job.id, reason, job.version);
    if (res.success) {
      loadJobs();
    } else {
      alert(res.message ?? "Cancellation failed.");
    }
  };

  // Campaign Actions
  const handlePause = async (campaignId: string) => {
    setCampaignActionRunning(campaignId);
    const res = await pauseCampaign(campaignId);
    setCampaignActionRunning(null);
    if (res.success) loadCampaigns();
    else alert(res.message ?? "Failed to pause campaign.");
  };

  const handleResume = async (campaignId: string) => {
    setCampaignActionRunning(campaignId);
    const res = await resumeCampaign(campaignId);
    setCampaignActionRunning(null);
    if (res.success) loadCampaigns();
    else alert(res.message ?? "Failed to resume campaign.");
  };

  const handleRunNow = async (campaignId: string) => {
    setCampaignActionRunning(campaignId);
    const res = await triggerCampaignRunNow(campaignId);
    setCampaignActionRunning(null);
    if (res.success) {
      loadCampaigns();
      alert("Manual scan run dispatched successfully.");
    } else {
      alert(res.message ?? "Failed to trigger run-now.");
    }
  };

  // Submit New Scan
  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    setCreating(true);
    setErrorMessage(null);

    const res = await createScanJob({
      targetUrl: targetUrl.trim(),
      scanProfile,
      providerKey: "bughunter",
    });

    setCreating(false);
    if (res.success) {
      setIsModalOpen(false);
      setTargetUrl("");
      loadJobs();
    } else {
      setErrorMessage(res.message ?? "Failed to create scan job.");
    }
  };

  const getStatusBadge = (status: number | string) => {
    const s = String(status).toLowerCase();
    if (s === "running" || s === "2") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
          Running
        </span>
      );
    }
    if (s === "validating" || s === "1") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
          Validating
        </span>
      );
    }
    if (s === "completed" || s === "3") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          Completed
        </span>
      );
    }
    if (s === "completedwithwarnings" || s === "4") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          Completed (Warnings)
        </span>
      );
    }
    if (s === "failed" || s === "6") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
          Failed
        </span>
      );
    }
    if (s === "cancelled" || s === "7") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-zinc-400"></span>
          Cancelled
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-zinc-800 text-zinc-300">
        Queued
      </span>
    );
  };

  const getProfileName = (profile: number | string) => {
    const p = String(profile).toLowerCase();
    if (p === "recon" || p === "0") return "Recon (Fast Probing)";
    if (p === "standard" || p === "webassessment" || p === "1") return "Standard (Web Assessment)";
    if (p === "deep" || p === "fullassessment" || p === "2") return "Deep (Full Assessment)";
    return String(profile);
  };

  const getCampaignStatusBadge = (status: string) => {
    switch (status) {
      case "Active":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">● Active</span>;
      case "Paused":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-zinc-800 text-zinc-400 border border-zinc-700">Paused</span>;
      case "AutoPaused":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">⚠ AutoPaused</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-zinc-800 text-zinc-500">{status}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Tab Switcher */}
      <div className="flex border-b border-zinc-800 gap-6">
        <button
          onClick={() => setActiveTab("jobs")}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "jobs"
              ? "border-indigo-500 text-indigo-400 font-semibold"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          Ad-Hoc Scan Jobs
        </button>
        <button
          onClick={() => setActiveTab("campaigns")}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "campaigns"
              ? "border-indigo-500 text-indigo-400 font-semibold"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Continuous Scan Campaigns
          {campaignHealth?.autoPausedCampaigns ? (
            <span className="px-1.5 py-0.2 bg-amber-500/20 text-amber-300 text-[10px] rounded-full">
              {campaignHealth.autoPausedCampaigns}
            </span>
          ) : null}
        </button>
      </div>

      {activeTab === "campaigns" ? (
        /* ================= CONTINUOUS CAMPAIGNS TAB ================= */
        <div className="space-y-6 animate-fadeIn">
          <CampaignHealthCard health={campaignHealth} loading={campaignsLoading} />

          {/* Campaigns Table */}
          <div className="bg-zinc-900/60 rounded-xl border border-zinc-800/80 overflow-hidden shadow-xl">
            <div className="p-4 border-b border-zinc-800/80 flex justify-between items-center bg-zinc-950/40">
              <div>
                <h3 className="text-sm font-semibold text-zinc-100">Configured Scan Campaigns</h3>
                <p className="text-xs text-zinc-400 mt-0.5">Recurring target assessments scheduled with durable distributed concurrency.</p>
              </div>
              <button
                onClick={() => loadCampaigns()}
                disabled={campaignsLoading}
                className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition flex items-center gap-1.5"
              >
                Refresh
              </button>
            </div>

            {campaignsLoading && campaigns.length === 0 ? (
              <div className="p-12 text-center text-zinc-500 text-sm">Loading campaigns...</div>
            ) : campaigns.length === 0 ? (
              <div className="p-12 text-center text-zinc-500 text-sm">No continuous scan campaigns configured yet.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-zinc-300">
                  <thead className="bg-zinc-900/90 text-zinc-400 uppercase text-[10px] tracking-wider border-b border-zinc-800">
                    <tr>
                      <th className="px-4 py-3">Campaign & Target</th>
                      <th className="px-4 py-3">Schedule</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Next Scheduled Run</th>
                      <th className="px-4 py-3">Failures</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {campaigns.map((c) => (
                      <tr key={c.id} className="hover:bg-zinc-800/30 transition-colors">
                        <td className="px-4 py-3.5">
                          <div className="font-semibold text-zinc-100">{c.name}</div>
                          <div className="text-[11px] text-zinc-400 truncate max-w-xs">{c.targetUrl ?? "Default Endpoint"}</div>
                        </td>
                        <td className="px-4 py-3.5 font-mono text-[11px]">
                          <div>{c.cronExpression ? `Cron: ${c.cronExpression}` : `Interval: ${c.intervalDuration ?? "24h"}`}</div>
                          <div className="text-zinc-500">{c.timeZoneId}</div>
                        </td>
                        <td className="px-4 py-3.5">
                          <div className="flex items-center gap-2">
                            {getCampaignStatusBadge(c.status)}
                            <span className="text-[10px] text-zinc-500 font-mono">v{c.scheduleVersion}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3.5 text-[11px]">
                          {c.nextRunUtc ? (
                            <div>
                              <div className="text-zinc-200">{new Date(c.nextRunUtc).toLocaleString()}</div>
                              <div className="text-zinc-500">
                                Last: {c.lastRunUtc ? new Date(c.lastRunUtc).toLocaleTimeString() : "Never"}
                              </div>
                            </div>
                          ) : (
                            <span className="text-zinc-500 italic">None scheduled</span>
                          )}
                        </td>
                        <td className="px-4 py-3.5">
                          <div className="flex items-center gap-1.5">
                            <span className={`font-mono font-medium ${c.consecutiveFailuresCount > 0 ? "text-amber-400" : "text-zinc-400"}`}>
                              {c.consecutiveFailuresCount}/{c.maxConsecutiveFailures}
                            </span>
                            {c.consecutiveFailuresCount > 0 && (
                              <button
                                onClick={() => setSelectedCampaignForDiag(c)}
                                className="text-[10px] text-indigo-400 hover:underline"
                              >
                                Diag
                              </button>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3.5 text-right space-x-1.5">
                          <button
                            onClick={() => setSelectedCampaignForHistory(c)}
                            className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-xs transition"
                          >
                            History
                          </button>
                          {c.status === "Active" ? (
                            <button
                              disabled={campaignActionRunning === c.id}
                              onClick={() => handlePause(c.id)}
                              className="px-2.5 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 rounded text-xs border border-amber-500/20 transition disabled:opacity-50"
                            >
                              Pause
                            </button>
                          ) : (
                            <button
                              disabled={campaignActionRunning === c.id}
                              onClick={() => handleResume(c.id)}
                              className="px-2.5 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 rounded text-xs border border-emerald-500/20 transition disabled:opacity-50"
                            >
                              Resume
                            </button>
                          )}
                          <button
                            disabled={campaignActionRunning === c.id}
                            onClick={() => handleRunNow(c.id)}
                            className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs transition disabled:opacity-50"
                          >
                            Run Now
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* ================= AD-HOC SCAN JOBS TAB ================= */
        <div className="space-y-6 animate-fadeIn">
          {/* Header Actions */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-zinc-900/60 p-4 rounded-xl border border-zinc-800 backdrop-blur-sm">
            <div>
              <h2 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
                Hosted Security Scanner Pipeline
              </h2>
              <p className="text-xs text-zinc-400 mt-0.5">
                Multi-tool sandboxed scans (Discovery → Probing → Assessment → Ingestion) with immutable provenance.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-zinc-800 text-zinc-200 text-xs px-3 py-2 rounded-lg border border-zinc-700 focus:outline-none focus:border-indigo-500"
              >
                <option value="">All Statuses</option>
                <option value="Running">Running</option>
                <option value="Completed">Completed</option>
                <option value="CompletedWithWarnings">Completed with Warnings</option>
                <option value="Failed">Failed</option>
                <option value="Cancelled">Cancelled</option>
              </select>
              <button
                onClick={() => setIsModalOpen(true)}
                className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition-colors shadow-lg shadow-indigo-600/20 flex items-center gap-1.5"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                Launch Security Scan
              </button>
            </div>
          </div>

          {/* Live Scan Jobs List */}
          <div className="bg-zinc-900/40 rounded-xl border border-zinc-800 overflow-hidden">
            {loading && jobs.length === 0 ? (
              <div className="p-8 text-center text-zinc-500 text-sm">Loading security scans...</div>
            ) : jobs.length === 0 ? (
              <div className="p-8 text-center text-zinc-500 text-sm">No security scans found.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-zinc-300">
                  <thead className="bg-zinc-900/80 text-zinc-400 uppercase text-[10px] tracking-wider border-b border-zinc-800">
                    <tr>
                      <th className="px-4 py-3">Target & Profile</th>
                      <th className="px-4 py-3">Status & Phase</th>
                      <th className="px-4 py-3">Live Progress</th>
                      <th className="px-4 py-3">Findings</th>
                      <th className="px-4 py-3">Created At</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60 font-mono">
                    {jobs.map((job) => {
                      const isRunning = String(job.status).toLowerCase() === "running" || String(job.status) === "2";
                      const canRetry = ["failed", "6", "cancelled", "7", "completedwithwarnings", "4"].includes(String(job.status).toLowerCase());
                      const canCancel = ["queued", "0", "validating", "1", "running", "2"].includes(String(job.status).toLowerCase());

                      return (
                        <tr key={job.id} className="hover:bg-zinc-800/30 transition-colors">
                          <td className="px-4 py-3.5">
                            <div className="font-semibold text-zinc-100">{job.targetUrl}</div>
                            <div className="text-[11px] text-zinc-400 font-sans mt-0.5">{getProfileName(job.scanProfile)}</div>
                          </td>
                          <td className="px-4 py-3.5 font-sans">
                            <div className="flex flex-col gap-1">
                              {getStatusBadge(job.status)}
                              {job.currentPhase && (
                                <span className="text-[11px] text-zinc-400">Phase: {job.currentPhase}</span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3.5">
                            <div className="w-full max-w-[140px] space-y-1">
                              <div className="flex justify-between text-[10px] text-zinc-400">
                                <span>{job.progressPercentage}%</span>
                                <span>{job.currentTool ?? "Idle"}</span>
                              </div>
                              <div className="w-full h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                                <div
                                  className={`h-full transition-all duration-300 ${
                                    isRunning ? "bg-indigo-500" : "bg-emerald-500"
                                  }`}
                                  style={{ width: `${job.progressPercentage}%` }}
                                ></div>
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-3.5">
                            <span className="font-bold text-amber-400">{job.totalFindingsCount}</span>
                          </td>
                          <td className="px-4 py-3.5 text-zinc-400 text-[11px]">
                            {new Date(job.createdAtUtc).toLocaleString()}
                          </td>
                          <td className="px-4 py-3.5 text-right space-x-2 font-sans">
                            <button
                              onClick={() => handleInspectReceipt(job)}
                              className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-xs transition"
                            >
                              Receipt
                            </button>
                            {canRetry && (
                              <button
                                onClick={() => handleRetry(job.id)}
                                className="px-2.5 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-400 border border-indigo-500/30 rounded text-xs transition"
                              >
                                Retry
                              </button>
                            )}
                            {canCancel && (
                              <button
                                onClick={() => handleCancel(job)}
                                className="px-2.5 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 rounded text-xs transition"
                              >
                                Cancel
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Campaign Execution History Drawer */}
      {selectedCampaignForHistory && (
        <CampaignHistoryDrawer
          campaignId={selectedCampaignForHistory.id}
          campaignName={selectedCampaignForHistory.name}
          onClose={() => setSelectedCampaignForHistory(null)}
        />
      )}

      {/* Campaign Diagnostics Modal */}
      {selectedCampaignForDiag && (
        <CampaignDiagnosticsModal
          campaignId={selectedCampaignForDiag.id}
          onClose={() => setSelectedCampaignForDiag(null)}
        />
      )}

      {/* Launch Scan Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex justify-between items-center">
              <h3 className="text-base font-semibold text-zinc-100">Launch New Security Scan</h3>
              <button onClick={() => setIsModalOpen(false)} className="text-zinc-500 hover:text-zinc-300">
                ✕
              </button>
            </div>
            {errorMessage && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg">
                {errorMessage}
              </div>
            )}
            <form onSubmit={handleCreateScan} className="space-y-4 text-xs">
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Target URL</label>
                <input
                  type="text"
                  placeholder="https://api.example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full bg-zinc-800 text-zinc-100 px-3 py-2 rounded-lg border border-zinc-700 focus:outline-none focus:border-indigo-500 font-mono"
                  required
                />
                <p className="text-[10px] text-zinc-500 mt-1">Must match an authorized security target domain.</p>
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Scan Profile</label>
                <select
                  value={scanProfile}
                  onChange={(e) => setScanProfile(Number(e.target.value))}
                  className="w-full bg-zinc-800 text-zinc-100 px-3 py-2 rounded-lg border border-zinc-700 focus:outline-none focus:border-indigo-500"
                >
                  <option value={0}>Recon (Fast Discovery & Probing — 10m ceiling)</option>
                  <option value={1}>Standard (Web Vulnerability Assessment — 20m ceiling)</option>
                  <option value={2}>Deep (Comprehensive Multi-Vector Assessment — 45m ceiling)</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition-colors disabled:opacity-50"
                >
                  {creating ? "Queuing..." : "Queue Scan Job"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Execution Receipt Modal */}
      {inspectingJob && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[85vh] overflow-y-auto">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
                  <span>Scan Execution Receipt</span>
                  {getStatusBadge(inspectingJob.status)}
                </h3>
                <p className="text-xs text-zinc-400 font-mono mt-0.5">{inspectingJob.targetUrl}</p>
              </div>
              <button
                onClick={() => {
                  setInspectingJob(null);
                  setSelectedReceipt(null);
                }}
                className="text-zinc-500 hover:text-zinc-300"
              >
                ✕
              </button>
            </div>

            {receiptLoading ? (
              <div className="py-8 text-center text-zinc-500 text-xs">Loading execution receipt...</div>
            ) : selectedReceipt ? (
              <div className="space-y-4 text-xs font-mono">
                {/* Summary Box */}
                <div className="bg-zinc-950 p-3 rounded-lg border border-zinc-800 text-zinc-300 font-sans">
                  <div className="text-[11px] text-zinc-400 font-semibold mb-1">Execution Summary</div>
                  <div>{selectedReceipt.summary}</div>
                  <div className="text-[11px] text-zinc-500 mt-2 flex gap-4">
                    <span>New Findings: {selectedReceipt.totalFindingsCreated}</span>
                    <span>Updated Findings: {selectedReceipt.totalFindingsUpdated}</span>
                  </div>
                </div>

                {/* Per-Tool Execution Receipts */}
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-zinc-300 font-sans">
                    Executed Scanners ({selectedReceipt.toolReceipts.length})
                  </div>
                  {selectedReceipt.toolReceipts.map((t, idx) => (
                    <div key={idx} className="bg-zinc-800/40 p-3 rounded-lg border border-zinc-800 space-y-2">
                      <div className="flex justify-between items-center font-sans">
                        <span className="font-semibold text-zinc-100">
                          {t.toolKey} <span className="text-zinc-400 font-normal">({t.version})</span>
                        </span>
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded font-semibold ${
                            String(t.status).toLowerCase() === "success" || String(t.status) === "0"
                              ? "bg-emerald-500/10 text-emerald-400"
                              : String(t.status).toLowerCase() === "skipped" || String(t.status) === "3"
                              ? "bg-amber-500/10 text-amber-400"
                              : "bg-rose-500/10 text-rose-400"
                          }`}
                        >
                          {String(t.status)}
                        </span>
                      </div>

                      {/* Immutable Provenance */}
                      <div className="text-[11px] text-zinc-400 space-y-0.5">
                        {t.executable && <div>Executable: <span className="text-zinc-200">{t.executable}</span></div>}
                        {t.containerImageRepository && (
                          <div>Image: <span className="text-zinc-200">{t.containerImageRepository}</span></div>
                        )}
                        {t.containerImageDigest && (
                          <div className="truncate text-zinc-500">Digest: {t.containerImageDigest}</div>
                        )}
                      </div>

                      {/* Output & Metrics */}
                      <div className="flex flex-wrap gap-4 text-[10px] text-zinc-400 border-t border-zinc-800/60 pt-1.5">
                        <span>Duration: {t.durationMs}ms</span>
                        <span>Output: {t.outputSizeBytes} bytes</span>
                        <span>Candidates: {t.candidatesParsed}</span>
                        <span>Findings Created: {t.findingsCreated}</span>
                      </div>

                      {t.failureReason && (
                        <div className="text-rose-400 text-[11px] bg-rose-500/10 p-2 rounded border border-rose-500/20 font-sans">
                          Failure Reason: {t.failureReason}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-zinc-500 text-xs">
                No execution receipt recorded yet for this scan job.
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => {
                  setInspectingJob(null);
                  setSelectedReceipt(null);
                }}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
