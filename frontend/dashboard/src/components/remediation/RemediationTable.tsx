"use client";

import { RemediationActionListDto } from "@/lib/remediation-api";

interface RemediationTableProps {
  actions: RemediationActionListDto[];
  onSelectAction: (action: RemediationActionListDto) => void;
}

export default function RemediationTable({ actions, onSelectAction }: RemediationTableProps) {
  if (actions.length === 0) {
    return (
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 rounded-xl p-12 text-center text-slate-400">
        <svg className="w-12 h-12 mx-auto mb-3 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <p className="font-medium text-slate-300">No remediation actions found</p>
        <p className="text-xs text-slate-500 mt-1">Try adjusting your filters or search query.</p>
      </div>
    );
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Proposed":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "PendingApproval":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "Approved":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "Executing":
        return "bg-blue-500/10 text-blue-400 border-blue-500/30 animate-pulse";
      case "VerificationPending":
        return "bg-indigo-500/10 text-indigo-400 border-indigo-500/30";
      case "Verified":
        return "bg-teal-500/10 text-teal-400 border-teal-500/30";
      case "VerificationFailed":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "Rejected":
      case "Failed":
        return "bg-slate-500/10 text-slate-400 border-slate-500/30";
      default:
        return "bg-slate-500/10 text-slate-400 border-slate-500/30";
    }
  };

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800 uppercase tracking-wider">
            <tr>
              <th className="py-3.5 px-4">Action & Rationale</th>
              <th className="py-3.5 px-4">Repository</th>
              <th className="py-3.5 px-4">Action Type</th>
              <th className="py-3.5 px-4">Provider</th>
              <th className="py-3.5 px-4">Pre-Risk</th>
              <th className="py-3.5 px-4">Status</th>
              <th className="py-3.5 px-4">Version</th>
              <th className="py-3.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {actions.map((action) => (
              <tr
                key={action.id}
                onClick={() => onSelectAction(action)}
                className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
              >
                <td className="py-3.5 px-4 max-w-xs">
                  <div className="font-semibold text-slate-100 group-hover:text-indigo-400 transition-colors truncate">
                    {action.title}
                  </div>
                  <div className="text-slate-500 truncate text-[11px] mt-0.5">{action.description}</div>
                </td>
                <td className="py-3.5 px-4 font-mono text-slate-400">{action.repositoryFullName}</td>
                <td className="py-3.5 px-4 font-mono text-slate-300">{action.actionType}</td>
                <td className="py-3.5 px-4">
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
                    {action.providerKey ?? "system"}
                  </span>
                </td>
                <td className="py-3.5 px-4">
                  {action.preExecutionRiskScore != null ? (
                    <span className="font-bold text-amber-400">{action.preExecutionRiskScore}</span>
                  ) : (
                    <span className="text-slate-600">-</span>
                  )}
                </td>
                <td className="py-3.5 px-4">
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold border ${getStatusBadge(action.status)}`}>
                    {action.status}
                  </span>
                </td>
                <td className="py-3.5 px-4 font-mono text-slate-500">v{action.version}</td>
                <td className="py-3.5 px-4 text-right">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectAction(action);
                    }}
                    className="inline-flex items-center px-2.5 py-1 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 text-[11px] font-medium transition-colors border border-indigo-500/30"
                  >
                    Details & Audit →
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
