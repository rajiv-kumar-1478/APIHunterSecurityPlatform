"use client";

import { useEffect, useState } from "react";
import { CampaignExecutionHistoryEntryDto, getCampaignHistory } from "@/lib/security-api";

interface CampaignHistoryDrawerProps {
  campaignId: string | null;
  campaignName?: string;
  onClose: () => void;
}

export function CampaignHistoryDrawer({ campaignId, campaignName, onClose }: CampaignHistoryDrawerProps) {
  const [history, setHistory] = useState<CampaignExecutionHistoryEntryDto[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [page, setPage] = useState<number>(1);

  useEffect(() => {
    if (!campaignId) return;

    let cancelled = false;
    void getCampaignHistory(campaignId, page, 25).then((data) => {
      if (cancelled) return;
      setHistory(data);
      setLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [campaignId, page]);

  if (!campaignId) return null;

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case "Dispatched":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "QueuedNext":
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      case "RecoveredStuck":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "SkippedClaimLost":
      case "RejectedConcurrent":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      default:
        return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-sm flex justify-end animate-fadeIn">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <span>Execution Audit & History</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">{campaignName ?? "Campaign"} ({campaignId})</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* History List */}
        <div className="flex-1 overflow-y-auto p-5 space-y-3">
          {loading ? (
            <div className="text-center py-12 text-slate-500 text-sm animate-pulse">Loading execution history...</div>
          ) : history.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-sm">No execution history recorded for this campaign yet.</div>
          ) : (
            history.map((entry) => (
              <div key={entry.auditLogId} className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 text-xs font-medium rounded-full border ${getDecisionBadge(entry.decision)}`}>
                      {entry.decision}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">v{entry.scheduleVersion}</span>
                  </div>
                  <span className="text-xs text-slate-500">
                    {new Date(entry.evaluatedAtUtc).toLocaleString()}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{entry.reason}</p>

                {/* Correlated Scan Job Details */}
                {entry.scanJobId && (
                  <div className="mt-2 pt-2 border-t border-slate-800/60 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    <div>
                      <span className="text-slate-500 block">Job Status:</span>
                      <span className="font-medium text-slate-200">{entry.scanJobStatus ?? "Pending"}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Findings:</span>
                      <span className="font-medium text-amber-400">{entry.totalFindingsCount ?? 0}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Duration:</span>
                      <span className="font-medium text-slate-300">
                        {entry.scanDurationSeconds ? `${entry.scanDurationSeconds.toFixed(0)}s` : "—"}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Target:</span>
                      <span className="font-mono text-slate-400 truncate block">{entry.targetUrl ?? "—"}</span>
                    </div>
                  </div>
                )}

                {entry.occurrenceKey && (
                  <div className="text-[11px] font-mono text-slate-500 truncate pt-1">
                    Key: {entry.occurrenceKey}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Footer Pagination */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
          <span>Page {page}</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => {
                setLoading(true);
                setPage((currentPage) => Math.max(1, currentPage - 1));
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-200 transition"
            >
              Previous
            </button>
            <button
              disabled={history.length < 25}
              onClick={() => {
                setLoading(true);
                setPage((currentPage) => currentPage + 1);
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-200 transition"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
