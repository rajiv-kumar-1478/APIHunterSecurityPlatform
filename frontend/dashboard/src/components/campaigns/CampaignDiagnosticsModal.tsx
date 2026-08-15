"use client";

import { useEffect, useState } from "react";
import { CampaignDiagnosticsDto, getCampaignDiagnostics } from "@/lib/security-api";

interface CampaignDiagnosticsModalProps {
  campaignId: string | null;
  onClose: () => void;
}

export function CampaignDiagnosticsModal({ campaignId, onClose }: CampaignDiagnosticsModalProps) {
  const [diag, setDiag] = useState<CampaignDiagnosticsDto | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    if (!campaignId) return;
    setLoading(true);
    getCampaignDiagnostics(campaignId).then((data) => {
      setDiag(data);
      setLoading(false);
    });
  }, [campaignId]);

  if (!campaignId) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <h3 className="text-base font-semibold text-slate-100">Campaign Diagnostics</h3>
              <p className="text-xs text-slate-400">{diag?.campaignName ?? "Loading..."}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition"
          >
            ✕
          </button>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-500 text-sm animate-pulse">Analyzing campaign diagnostics...</div>
        ) : !diag ? (
          <div className="py-8 text-center text-slate-500 text-sm">Failed to load diagnostics.</div>
        ) : (
          <div className="space-y-4 text-xs">
            {/* Status Summary */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Campaign Status:</span>
                <span className="font-semibold text-slate-200">{diag.status}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Consecutive Failures:</span>
                <span className={`font-semibold ${diag.consecutiveFailuresCount >= diag.maxConsecutiveFailures ? "text-rose-400" : "text-amber-400"}`}>
                  {diag.consecutiveFailuresCount} / {diag.maxConsecutiveFailures} max
                </span>
              </div>
              {diag.isOverdue && (
                <div className="flex justify-between items-center text-rose-400">
                  <span>Overdue Status:</span>
                  <span>Yes (by {diag.overdueBy ?? "—"})</span>
                </div>
              )}
              {diag.autoPauseReason && (
                <div className="pt-2 border-t border-slate-800 text-amber-300/90">
                  <span className="font-medium block text-amber-400 mb-0.5">Auto-Pause Reason:</span>
                  {diag.autoPauseReason}
                </div>
              )}
            </div>

            {/* Failure Streak */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Recent Failure Events</h4>
              {diag.recentFailureStreak.length === 0 ? (
                <div className="text-slate-500 italic p-3 bg-slate-950/40 rounded-lg border border-slate-800/40">No recent failure events.</div>
              ) : (
                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {diag.recentFailureStreak.map((f, i) => (
                    <div key={i} className="p-2.5 bg-rose-500/5 border border-rose-500/20 rounded-lg space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="font-semibold text-rose-400">{f.failureType}</span>
                        <span className="text-slate-500">{new Date(f.timestampUtc).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-slate-300 text-[11px] leading-snug">{f.reason}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recoveries */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Audit-Sourced Stuck Recoveries</h4>
              {diag.recentRecoveries.length === 0 ? (
                <div className="text-slate-500 italic p-3 bg-slate-950/40 rounded-lg border border-slate-800/40">No stuck-job recoveries recorded.</div>
              ) : (
                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {diag.recentRecoveries.map((r, i) => (
                    <div key={i} className="p-2.5 bg-amber-500/5 border border-amber-500/20 rounded-lg space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="font-semibold text-amber-400">RecoveredStuck</span>
                        <span className="text-slate-500">{new Date(r.recoveredAtUtc).toLocaleString()}</span>
                      </div>
                      <p className="text-slate-300 text-[11px] leading-snug">{r.reason}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-xl transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
