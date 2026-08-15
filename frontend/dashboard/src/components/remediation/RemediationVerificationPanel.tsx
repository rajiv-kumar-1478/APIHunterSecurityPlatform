"use client";

import { useState } from "react";
import { RemediationActionDetailDto, verifyRemediationAction } from "@/lib/remediation-api";

interface RemediationVerificationPanelProps {
  action: RemediationActionDetailDto;
  onSuccess: () => void;
  onConcurrencyConflict: () => void;
}

export default function RemediationVerificationPanel({ action, onSuccess, onConcurrencyConflict }: RemediationVerificationPanelProps) {
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const verification = action.verification;
  const canVerify = action.status === "VerificationPending";

  const handleVerify = async () => {
    setError(null);
    setIsVerifying(true);
    try {
      await verifyRemediationAction(action.id, action.version);
      onSuccess();
    } catch (err: any) {
      if (err.isConcurrencyConflict) {
        setError(err.message);
        onConcurrencyConflict();
      } else {
        setError(err.message || "Verification failed.");
      }
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 my-4">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Post-Remediation Verification & Risk Delta
        </h4>
        {verification && (
          <span
            className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
              verification.status === "Verified"
                ? "bg-teal-500/10 text-teal-400 border-teal-500/30"
                : "bg-rose-500/10 text-rose-400 border-rose-500/30"
            }`}
          >
            {verification.status}
          </span>
        )}
      </div>

      {error && (
        <div className="mb-3 p-2.5 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      {verification ? (
        <div className="grid grid-cols-3 gap-3 mb-3">
          <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-center">
            <div className="text-[10px] uppercase font-semibold text-slate-400">Pre-Risk</div>
            <div className="text-xl font-bold text-amber-400 mt-0.5">{verification.preExecutionRiskScore}</div>
          </div>
          <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-center">
            <div className="text-[10px] uppercase font-semibold text-slate-400">Post-Risk</div>
            <div className="text-xl font-bold text-teal-400 mt-0.5">{verification.postExecutionRiskScore}</div>
          </div>
          <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-center">
            <div className="text-[10px] uppercase font-semibold text-slate-400">Risk Delta</div>
            <div className="text-xl font-bold text-indigo-400 mt-0.5">-{verification.riskDelta}</div>
          </div>
        </div>
      ) : (
        <div className="text-xs text-slate-400 mb-3">
          Verification is pending. Run verification to confirm the security condition was removed.
        </div>
      )}

      {canVerify && (
        <div className="flex items-center justify-end">
          <button
            disabled={isVerifying}
            onClick={handleVerify}
            className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition-colors shadow-lg shadow-indigo-600/20 disabled:opacity-50"
          >
            {isVerifying ? "Verifying Provider Status..." : "Run Post-Remediation Verification"}
          </button>
        </div>
      )}
    </div>
  );
}
