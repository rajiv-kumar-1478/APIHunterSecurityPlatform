"use client";

import { useEffect, useState } from "react";
import {
  RemediationActionDetailDto,
  RemediationActionHistoryDto,
  fetchRemediationActionById,
  fetchRemediationHistory,
} from "@/lib/remediation-api";
import RemediationApprovalPanel from "./RemediationApprovalPanel";
import RemediationExecutionStatus from "./RemediationExecutionStatus";
import RemediationVerificationPanel from "./RemediationVerificationPanel";
import RemediationTimeline from "./RemediationTimeline";

interface RemediationDetailDrawerProps {
  actionId: string | null;
  onClose: () => void;
  onRefreshList: () => void;
}

export default function RemediationDetailDrawer({ actionId, onClose, onRefreshList }: RemediationDetailDrawerProps) {
  const [detail, setDetail] = useState<RemediationActionDetailDto | null>(null);
  const [history, setHistory] = useState<RemediationActionHistoryDto[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [concurrencyNotice, setConcurrencyNotice] = useState<string | null>(null);

  const loadData = async (id: string) => {
    setIsLoading(true);
    setConcurrencyNotice(null);
    try {
      const actionDetail = await fetchRemediationActionById(id);
      const actionHistory = await fetchRemediationHistory(id);
      setDetail(actionDetail);
      setHistory(actionHistory);
    } catch (err: any) {
      console.error("Failed to load remediation detail:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (actionId) {
      loadData(actionId);
    } else {
      setDetail(null);
      setHistory([]);
    }
  }, [actionId]);

  if (!actionId) return null;

  const handleConcurrencyConflict = () => {
    setConcurrencyNotice("Stale action version detected. The action was modified concurrently. Data refreshed below.");
    if (actionId) loadData(actionId);
    onRefreshList();
  };

  const handleActionSuccess = () => {
    if (actionId) loadData(actionId);
    onRefreshList();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-sm flex justify-end transition-opacity">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded border border-indigo-500/30 font-semibold">
                Action Detail
              </span>
              {detail && (
                <span className="text-xs font-mono text-slate-400">
                  Version v{detail.version}
                </span>
              )}
            </div>
            <h3 className="text-base font-bold text-slate-100">{detail?.title ?? "Loading Details..."}</h3>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {concurrencyNotice && (
            <div className="p-3 bg-amber-950/50 border border-amber-700/60 rounded-xl text-xs text-amber-300 flex items-center gap-2">
              <svg className="w-4 h-4 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              {concurrencyNotice}
            </div>
          )}

          {isLoading ? (
            <div className="py-16 text-center text-slate-500 text-xs">
              <div className="inline-block w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mb-2" />
              <p>Fetching remediation action state...</p>
            </div>
          ) : detail ? (
            <>
              {/* Finding & Rationale Context */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2">Finding Context</h4>
                <div className="text-xs text-slate-300 space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Finding Title:</span>
                    <span className="font-medium text-slate-100">{detail.findingTitle}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Finding Severity:</span>
                    <span className="font-semibold text-rose-400">{detail.findingSeverity}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Repository:</span>
                    <span className="font-mono text-slate-300">{detail.repositoryFullName}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Resource Ref:</span>
                    <span className="font-mono text-slate-300">{detail.providerResourceReference ?? "N/A"}</span>
                  </div>
                </div>
              </div>

              {/* Approval Panel */}
              <RemediationApprovalPanel
                action={detail}
                onSuccess={handleActionSuccess}
                onConcurrencyConflict={handleConcurrencyConflict}
              />

              {/* Execution Status Panel */}
              <RemediationExecutionStatus
                action={detail}
                onSuccess={handleActionSuccess}
                onConcurrencyConflict={handleConcurrencyConflict}
              />

              {/* Verification Panel */}
              <RemediationVerificationPanel
                action={detail}
                onSuccess={handleActionSuccess}
                onConcurrencyConflict={handleConcurrencyConflict}
              />

              {/* History Timeline */}
              <RemediationTimeline history={history} />
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}
