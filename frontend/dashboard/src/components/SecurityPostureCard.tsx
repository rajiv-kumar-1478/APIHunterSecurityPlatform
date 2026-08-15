"use client";

import { SecurityPosture } from "@/lib/security-api";

interface Props {
  posture: SecurityPosture | null;
}

export function SecurityPostureCard({ posture }: Props) {
  if (!posture) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="glass-card p-5 animate-pulse h-28" />
        ))}
      </div>
    );
  }

  const severityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return "var(--accent-red)";
      case "high": return "#f97316";
      case "medium": return "#eab308";
      case "low": return "var(--accent-cyan)";
      default: return "var(--text-muted)";
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6 fade-in">
      {/* Risk Score Gauge */}
      <div className="glass-card p-5 border-l-4" style={{ borderLeftColor: severityColor(posture.overallSeverity) }}>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
            Highest Repo Risk
          </span>
          <span className="text-xs font-bold px-2 py-0.5 rounded"
            style={{ background: `${severityColor(posture.overallSeverity)}20`, color: severityColor(posture.overallSeverity) }}>
            {posture.overallSeverity}
          </span>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-bold" style={{ fontFamily: "Outfit, sans-serif", color: severityColor(posture.overallSeverity) }}>
            {posture.highestRepositoryRiskScore}
          </span>
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>/ 100</span>
        </div>
        <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
          Persisted RiskEngine Score
        </p>
      </div>

      {/* Open Findings */}
      <div className="glass-card p-5 border-l-4" style={{ borderLeftColor: "var(--accent-purple)" }}>
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
          Active Findings
        </span>
        <div className="flex items-baseline gap-2 mt-2">
          <span className="text-3xl font-bold" style={{ fontFamily: "Outfit, sans-serif", color: "var(--text-primary)" }}>
            {posture.openFindingsCount}
          </span>
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>open</span>
        </div>
        <div className="flex gap-2 mt-2 text-xs">
          <span className="px-1.5 py-0.5 rounded" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>
            {posture.criticalFindingsCount} Critical
          </span>
          <span className="px-1.5 py-0.5 rounded" style={{ background: "rgba(249,115,22,0.15)", color: "#f97316" }}>
            {posture.highFindingsCount} High
          </span>
        </div>
      </div>

      {/* Monitored Repositories */}
      <div className="glass-card p-5 border-l-4" style={{ borderLeftColor: "var(--accent-cyan)" }}>
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
          Monitored Repos
        </span>
        <div className="flex items-baseline gap-2 mt-2">
          <span className="text-3xl font-bold" style={{ fontFamily: "Outfit, sans-serif", color: "var(--accent-cyan)" }}>
            {posture.totalRepositoriesMonitored}
          </span>
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>repositories</span>
        </div>
        <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
          Tracked in platform DB
        </p>
      </div>

      {/* Validated Credentials */}
      <div className="glass-card p-5 border-l-4" style={{ borderLeftColor: "var(--accent-green)" }}>
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
          Validated Credentials
        </span>
        <div className="flex items-baseline gap-2 mt-2">
          <span className="text-3xl font-bold" style={{ fontFamily: "Outfit, sans-serif", color: "var(--accent-green)" }}>
            {posture.validatedCredentialsCount}
          </span>
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>active</span>
        </div>
        <p className="text-xs mt-2" style={{ color: "var(--text-muted)" }}>
          Phase 5 & 6 Validation Truth
        </p>
      </div>
    </div>
  );
}
