"use client";

import { RemediationSummary } from "@/lib/remediation-api";

interface RemediationSummaryProps {
  summary: RemediationSummary | null;
  selectedStatus: string;
  onSelectStatus: (status: string) => void;
}

export default function RemediationSummaryCards({ summary, selectedStatus, onSelectStatus }: RemediationSummaryProps) {
  if (!summary) return null;

  const cards = [
    { label: "Total Actions", count: summary.totalActions, statusKey: "", color: "border-slate-700 bg-slate-900/60 text-slate-200" },
    { label: "Proposed", count: summary.proposedCount, statusKey: "Proposed", color: "border-cyan-500/30 bg-cyan-950/20 text-cyan-400" },
    { label: "Pending Approval", count: summary.pendingApprovalCount, statusKey: "PendingApproval", color: "border-amber-500/30 bg-amber-950/20 text-amber-400" },
    { label: "Approved", count: summary.approvedCount, statusKey: "Approved", color: "border-emerald-500/30 bg-emerald-950/20 text-emerald-400" },
    { label: "Executing", count: summary.executingCount, statusKey: "Executing", color: "border-blue-500/30 bg-blue-950/20 text-blue-400" },
    { label: "Verification Pending", count: summary.verificationPendingCount, statusKey: "VerificationPending", color: "border-indigo-500/30 bg-indigo-950/20 text-indigo-400" },
    { label: "Verified", count: summary.verifiedCount, statusKey: "Verified", color: "border-teal-500/30 bg-teal-950/20 text-teal-400" },
    { label: "Verification Failed", count: summary.verificationFailedCount, statusKey: "VerificationFailed", color: "border-rose-500/30 bg-rose-950/20 text-rose-400" },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 mb-6">
      {cards.map((card) => {
        const isSelected = selectedStatus === card.statusKey;
        return (
          <button
            key={card.label}
            onClick={() => onSelectStatus(card.statusKey)}
            className={`p-3 rounded-xl border transition-all text-left group hover:scale-[1.02] ${card.color} ${
              isSelected ? "ring-2 ring-indigo-500 shadow-lg shadow-indigo-500/10" : ""
            }`}
          >
            <div className="text-2xl font-bold tracking-tight mb-1">{card.count}</div>
            <div className="text-xs font-medium opacity-80 truncate">{card.label}</div>
          </button>
        );
      })}
    </div>
  );
}
