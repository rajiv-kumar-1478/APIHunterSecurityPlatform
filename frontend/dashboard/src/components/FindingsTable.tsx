"use client";

import { PagedResult, SecurityFinding } from "@/lib/security-api";

interface Props {
  data: PagedResult<SecurityFinding>;
  loading: boolean;
  onPageChange: (page: number) => void;
  onSelectFinding: (finding: SecurityFinding) => void;
}

export function FindingsTable({ data, loading, onPageChange, onSelectFinding }: Props) {
  const totalPages = Math.ceil(data.totalCount / data.pageSize) || 1;

  const severityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-950 text-red-400 border border-red-800">Critical</span>;
      case "high": return <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-950 text-orange-400 border border-orange-800">High</span>;
      case "medium": return <span className="px-2 py-0.5 rounded text-xs font-bold bg-yellow-950 text-yellow-400 border border-yellow-800">Medium</span>;
      case "low": return <span className="px-2 py-0.5 rounded text-xs font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">Low</span>;
      default: return <span className="px-2 py-0.5 rounded text-xs font-bold bg-gray-800 text-gray-400">{sev}</span>;
    }
  };

  const statusBadge = (st: string) => {
    switch (st) {
      case "Open": return <span className="px-2 py-0.5 rounded text-xs bg-blue-950 text-blue-300 border border-blue-800 font-mono">Open</span>;
      case "Investigating": return <span className="px-2 py-0.5 rounded text-xs bg-purple-950 text-purple-300 border border-purple-800 font-mono">Investigating</span>;
      case "Confirmed": return <span className="px-2 py-0.5 rounded text-xs bg-red-950 text-red-300 border border-red-800 font-mono">Confirmed</span>;
      case "Remediated": return <span className="px-2 py-0.5 rounded text-xs bg-green-950 text-green-300 border border-green-800 font-mono">Remediated</span>;
      case "AcceptedRisk": return <span className="px-2 py-0.5 rounded text-xs bg-yellow-950 text-yellow-300 border border-yellow-800 font-mono">Accepted Risk</span>;
      case "FalsePositive": return <span className="px-2 py-0.5 rounded text-xs bg-gray-900 text-gray-400 border border-gray-700 font-mono">False Positive</span>;
      case "Resolved": return <span className="px-2 py-0.5 rounded text-xs bg-teal-950 text-teal-300 border border-teal-800 font-mono">Resolved</span>;
      default: return <span className="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-400 font-mono">{st}</span>;
    }
  };

  return (
    <div className="glass-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/80 border-b border-slate-800 text-muted uppercase tracking-wider font-semibold">
            <tr>
              <th className="p-3">Severity</th>
              <th className="p-3">Title & Finding Type</th>
              <th className="p-3">Risk Score</th>
              <th className="p-3">Status</th>
              <th className="p-3">Last Observed</th>
              <th className="p-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {loading ? (
              <tr>
                <td colSpan={6} className="p-6 text-center text-muted">
                  Loading security findings inventory…
                </td>
              </tr>
            ) : data.items.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-6 text-center text-muted">
                  No security findings match the active criteria.
                </td>
              </tr>
            ) : (
              data.items.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => onSelectFinding(item)}
                  className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                >
                  <td className="p-3">{severityBadge(item.severity)}</td>
                  <td className="p-3">
                    <p className="font-semibold text-foreground">{item.title}</p>
                    <p className="text-[10px] text-muted font-mono">{item.findingType}</p>
                  </td>
                  <td className="p-3 font-mono font-bold text-sm">
                    {item.riskScore}
                  </td>
                  <td className="p-3">{statusBadge(item.status)}</td>
                  <td className="p-3 text-muted text-[11px]">
                    {new Date(item.lastObservedAtUtc).toLocaleDateString()}
                  </td>
                  <td className="p-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding(item);
                      }}
                      className="px-2.5 py-1 text-xs rounded border border-cyan-800 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      <div className="flex items-center justify-between p-3 bg-slate-900/60 border-t border-slate-800 text-xs text-muted">
        <span>
          Showing {data.items.length} of {data.totalCount} findings (Page {data.page} of {totalPages})
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(data.page - 1)}
            disabled={data.page <= 1 || loading}
            className="px-3 py-1 rounded border border-slate-700 disabled:opacity-40 hover:bg-slate-800 text-foreground"
          >
            Previous
          </button>
          <button
            onClick={() => onPageChange(data.page + 1)}
            disabled={data.page >= totalPages || loading}
            className="px-3 py-1 rounded border border-slate-700 disabled:opacity-40 hover:bg-slate-800 text-foreground"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
