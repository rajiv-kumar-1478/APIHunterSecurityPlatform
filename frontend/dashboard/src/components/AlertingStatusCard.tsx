"use client";

import { AlertingStatus } from "@/lib/security-api";

interface Props {
  status: AlertingStatus | null;
}

export function AlertingStatusCard({ status }: Props) {
  if (!status) {
    return (
      <div className="glass-card p-4 mb-6 animate-pulse text-xs text-muted">
        Loading alerting status…
      </div>
    );
  }

  return (
    <div className="glass-card p-4 mb-6">
      <div className="flex items-center justify-between border-b pb-2 mb-3" style={{ borderColor: "var(--border-subtle)" }}>
        <h4 className="text-sm font-semibold flex items-center gap-2">
          <span>🔔</span> Alert Subsystem Status (Read-Only)
        </h4>
        <span className={`text-xs px-2 py-0.5 rounded font-bold uppercase ${status.enabled ? "bg-green-950 text-green-400 border border-green-800" : "bg-red-950 text-red-400 border border-red-800"}`}>
          {status.enabled ? "Enabled" : "Disabled (Fail-Closed)"}
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
        <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
          <span className="block text-[10px] text-muted uppercase tracking-wider">Cooldown Window</span>
          <span className="font-bold text-foreground">{status.cooldownMinutes} minutes</span>
        </div>
        <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
          <span className="block text-[10px] text-muted uppercase tracking-wider">High Threshold</span>
          <span className="font-bold text-orange-400">Score &ge; {status.highSeverityThreshold}</span>
        </div>
        <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
          <span className="block text-[10px] text-muted uppercase tracking-wider">Critical Threshold</span>
          <span className="font-bold text-red-400">Score &ge; {status.criticalSeverityThreshold}</span>
        </div>
        <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
          <span className="block text-[10px] text-muted uppercase tracking-wider">Risk Jump Delta</span>
          <span className="font-bold text-cyan-400">&Delta; &ge; +{status.riskJumpThreshold} points</span>
        </div>
      </div>
    </div>
  );
}
