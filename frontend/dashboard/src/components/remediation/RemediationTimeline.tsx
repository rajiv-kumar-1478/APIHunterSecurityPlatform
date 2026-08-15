"use client";

import { RemediationActionHistoryDto } from "@/lib/remediation-api";

interface RemediationTimelineProps {
  history: RemediationActionHistoryDto[];
}

export default function RemediationTimeline({ history }: RemediationTimelineProps) {
  if (history.length === 0) {
    return <div className="text-xs text-slate-500 italic p-3">No history events recorded yet.</div>;
  }

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 my-4">
      <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
        <svg className="w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        Immutable Audit & History Timeline
      </h4>

      <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {history.map((event) => (
          <div key={event.id} className="relative group">
            <div className="absolute -left-6 top-1.5 w-2.5 h-2.5 rounded-full bg-indigo-500 border-2 border-slate-950 ring-2 ring-indigo-500/20" />
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className="text-xs font-semibold text-slate-200">
                  {event.fromStatus ? `${event.fromStatus} → ${event.toStatus}` : `Status set to ${event.toStatus}`}
                </span>
                <span className="text-[10px] text-slate-500 font-mono">
                  {new Date(event.createdAtUtc).toLocaleString()}
                </span>
              </div>

              {event.reason && <p className="text-xs text-slate-400 mt-1 leading-relaxed">{event.reason}</p>}

              {event.changedByUserName && (
                <div className="text-[10px] text-slate-500 mt-2">
                  Actor: <span className="text-slate-300 font-medium">{event.changedByUserName}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
