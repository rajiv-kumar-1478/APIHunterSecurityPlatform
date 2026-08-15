"use client";

import { StatusHistory } from "@/lib/security-api";

interface Props {
  history: StatusHistory[];
  loading: boolean;
}

export function LifecycleTimeline({ history, loading }: Props) {
  if (loading) {
    return <div className="text-xs text-muted py-4 text-center">Loading governance history…</div>;
  }

  if (history.length === 0) {
    return <div className="text-xs text-muted py-4 text-center">No status transitions recorded yet.</div>;
  }

  return (
    <div className="glass-card p-4 mb-4">
      <h4 className="text-sm font-semibold mb-3 flex items-center gap-2 border-b pb-2" style={{ borderColor: "var(--border-subtle)" }}>
        <span>📜</span> Governance Lifecycle Audit Trail ({history.length})
      </h4>

      <div className="space-y-3 relative pl-4 border-l" style={{ borderColor: "var(--border-subtle)" }}>
        {history.map((h) => (
          <div key={h.id} className="relative">
            <div className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-purple-500 border border-background" />

            <div className="p-3 rounded border text-xs" style={{ background: "rgba(255,255,255,0.02)", borderColor: "var(--border-subtle)" }}>
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  {h.fromStatus && (
                    <span className="text-muted font-mono">{h.fromStatus} ➔</span>
                  )}
                  <span className="font-bold text-purple-400 font-mono">{h.toStatus}</span>
                </div>
                <span className="text-[10px] text-muted">
                  {new Date(h.createdAtUtc).toLocaleString()}
                </span>
              </div>

              <p className="text-foreground mt-1">
                <strong>Reason:</strong> <span className="text-gray-300">{h.reason}</span>
              </p>

              {h.changedByUserId && (
                <p className="text-[10px] text-muted mt-1">
                  Actor ID: {h.changedByUserId}
                </p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
