"use client";

import { useState } from "react";
import {
  RemediationActionDetailDto,
  approveRemediationAction,
  isRemediationConcurrencyError,
  rejectRemediationAction,
} from "@/lib/remediation-api";
import { getErrorMessage } from "@/lib/api-client";

interface RemediationApprovalPanelProps {
  action: RemediationActionDetailDto;
  onSuccess: () => void;
  onConcurrencyConflict: () => void;
}

export default function RemediationApprovalPanel({ action, onSuccess, onConcurrencyConflict }: RemediationApprovalPanelProps) {
  const [reason, setReason] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canApprove = action.status === "Proposed" || action.status === "PendingApproval";

  if (!canApprove) return null;

  const handleApprove = async () => {
    if (!reason.trim()) {
      setError("Reason is mandatory for approval.");
      return;
    }
    setError(null);
    setIsSubmitting(true);
    try {
      await approveRemediationAction(action.id, action.version, reason.trim());
      onSuccess();
    } catch (error: unknown) {
      if (isRemediationConcurrencyError(error)) {
        setError(error.message);
        onConcurrencyConflict();
      } else {
        setError(getErrorMessage(error, "Approval failed."));
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReject = async () => {
    if (!reason.trim()) {
      setError("Reason is mandatory for rejection.");
      return;
    }
    setError(null);
    setIsSubmitting(true);
    try {
      await rejectRemediationAction(action.id, action.version, reason.trim());
      onSuccess();
    } catch (error: unknown) {
      if (isRemediationConcurrencyError(error)) {
        setError(error.message);
        onConcurrencyConflict();
      } else {
        setError(getErrorMessage(error, "Rejection failed."));
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 my-4">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          Governance Approval Panel
        </h4>
        <span className="text-[10px] font-mono bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
          Version v{action.version}
        </span>
      </div>

      {error && (
        <div className="mb-3 p-2.5 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      <div className="mb-3">
        <label className="block text-[11px] font-semibold text-slate-400 mb-1">
          Reason / Governance Rationale <span className="text-rose-400">*</span>
        </label>
        <textarea
          rows={2}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Provide explicit security rationale for approval or rejection..."
          className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        />
      </div>

      <div className="flex items-center justify-end gap-2">
        <button
          disabled={isSubmitting}
          onClick={handleReject}
          className="px-3.5 py-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 text-xs font-semibold transition-colors border border-rose-800/50 disabled:opacity-50"
        >
          Reject Action
        </button>
        <button
          disabled={isSubmitting}
          onClick={handleApprove}
          className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors shadow-lg shadow-emerald-600/20 disabled:opacity-50"
        >
          Approve Action
        </button>
      </div>
    </div>
  );
}
