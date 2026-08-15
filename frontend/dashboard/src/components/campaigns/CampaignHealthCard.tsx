"use client";

import { CampaignOperationalHealthDto } from "@/lib/security-api";

interface CampaignHealthCardProps {
  health: CampaignOperationalHealthDto | null;
  loading: boolean;
}

export function CampaignHealthCard({ health, loading }: CampaignHealthCardProps) {
  if (loading && !health) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 animate-pulse">
        <div className="h-4 bg-slate-800 rounded w-1/4 mb-3"></div>
        <div className="h-8 bg-slate-800 rounded w-1/2"></div>
      </div>
    );
  }

  if (!health) return null;

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Healthy":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "Degraded":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "Unavailable":
      case "FailClosed":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      default:
        return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm shadow-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Campaign Scheduler Health</h3>
            <p className="text-xs text-slate-400 mt-0.5">{health.statusReason}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className={`px-3 py-1 text-xs font-semibold rounded-full border ${getStatusColor(health.status)}`}>
            ● {health.status}
          </span>
          <span className={`px-2.5 py-1 text-xs rounded-full border ${health.schedulerWorkerAlive ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-rose-500/10 text-rose-400 border-rose-500/20"}`}>
            Worker: {health.schedulerWorkerAlive ? "Alive" : "Stale"}
          </span>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-4">
        <div className="bg-slate-950/60 border border-slate-800/60 rounded-lg p-3">
          <div className="text-xs text-slate-400">Active Campaigns</div>
          <div className="text-xl font-bold text-slate-100 mt-1">{health.activeCampaigns} <span className="text-xs font-normal text-slate-500">/ {health.totalCampaigns}</span></div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/60 rounded-lg p-3">
          <div className="text-xs text-slate-400">AutoPaused</div>
          <div className={`text-xl font-bold mt-1 ${health.autoPausedCampaigns > 0 ? "text-amber-400" : "text-slate-300"}`}>
            {health.autoPausedCampaigns}
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/60 rounded-lg p-3">
          <div className="text-xs text-slate-400">Overdue</div>
          <div className={`text-xl font-bold mt-1 ${health.overdueCampaignsCount > 0 ? "text-rose-400" : "text-slate-300"}`}>
            {health.overdueCampaignsCount}
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/60 rounded-lg p-3">
          <div className="text-xs text-slate-400">24h Dispatched</div>
          <div className="text-xl font-bold text-indigo-400 mt-1">{health.metrics24h?.dispatchedCount ?? 0}</div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/60 rounded-lg p-3">
          <div className="text-xs text-slate-400">24h Success Rate</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">
            {health.metrics24h?.successRatePercentage?.toFixed(1) ?? "100.0"}%
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/60 rounded-lg p-3">
          <div className="text-xs text-slate-400">Avg Duration (24h)</div>
          <div className="text-xl font-bold text-slate-200 mt-1">
            {(health.metrics24h?.averageScanDurationSeconds ?? 0).toFixed(0)}s
          </div>
        </div>
      </div>
    </div>
  );
}
