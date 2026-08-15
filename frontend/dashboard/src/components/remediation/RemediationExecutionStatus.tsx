"use client";

import { useState } from "react";
import { RemediationActionDetailDto, executeRemediationAction } from "@/lib/remediation-api";

interface RemediationExecutionStatusProps {
  action: RemediationActionDetailDto;
  onSuccess: () => void;
  onConcurrencyConflict: () => void;
}

export default function RemediationExecutionStatus({ action, onSuccess, onConcurrencyConflict }: RemediationExecutionStatusProps) {
  const [isExecuting, setIsExecuting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canExecute = action.status === "Approved";
  const isCurrentlyExecuting = action.status === "Executing";

  const handleExecute = async () => {
    setError(null);
    setIsExecuting(true);
    try {
      await executeRemediationAction(action.id, action.version);
      onSuccess();
    } catch (err: any) {
      if (err.isConcurrencyConflict) {
        setError(err.message);
        onConcurrencyConflict();
      } else {
        setError(err.message || "Provider execution failed.");
      }
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 my-4">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          Provider Execution Status
        </h4>
        <span className="text-[10px] font-mono bg-blue-950/40 text-blue-300 px-2 py-0.5 rounded border border-blue-800/40">
          Provider: {action.providerKey ?? "github"}
        </span>
      </div>

      {error && (
        <div className="mb-3 p-2.5 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      )}

      <div className="text-xs text-slate-400 mb-3 leading-relaxed">
        <p>
          Resource Target: <span className="font-mono text-slate-200">{action.providerResourceReference ?? "N/A"}</span>
        </p>
        {action.executionStartedAtUtc && (
          <p className="text-[11px] text-slate-500 mt-1">
            Execution Started: {new Date(action.executionStartedAtUtc).toLocaleString()}
          </p>
        )}
      </div>

      {canExecute && (
        <div className="flex items-center justify-end">
          <button
            disabled={isExecuting}
            onClick={handleExecute}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-colors shadow-lg shadow-blue-600/20 disabled:opacity-50 flex items-center gap-1.5"
          >
            {isExecuting ? "Executing Provider Operation..." : "Trigger Provider Execution"}
          </button>
        </div>
      )}

      {isCurrentlyExecuting && (
        <div className="p-3 bg-blue-950/30 border border-blue-800/40 rounded-lg text-xs text-blue-300 flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-blue-400 animate-ping" />
          Provider operation running in background...
        </div>
      )}
    </div>
  );
}
