"use client";

import { RiskFactor } from "@/lib/security-api";

interface Props {
  riskScore: number;
  severity: string;
  factorBreakdownJson: string;
}

export function RiskBreakdown({ riskScore, severity, factorBreakdownJson }: Props) {
  let factors: RiskFactor[] = [];
  try {
    factors = JSON.parse(factorBreakdownJson);
  } catch {
    factors = [];
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
    <div className="glass-card p-4 mb-4">
      <div className="flex items-center justify-between mb-3 border-b pb-2" style={{ borderColor: "var(--border-subtle)" }}>
        <h4 className="text-sm font-semibold flex items-center gap-2">
          <span>🎯</span> Deterministic Risk Breakdown
        </h4>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted font-medium">Risk Score:</span>
          <span className="text-lg font-bold" style={{ color: severityColor(severity), fontFamily: "Outfit, sans-serif" }}>
            {riskScore} / 100
          </span>
          <span className="text-xs px-2 py-0.5 rounded font-bold uppercase"
            style={{ background: `${severityColor(severity)}20`, color: severityColor(severity) }}>
            {severity}
          </span>
        </div>
      </div>

      <p className="text-xs text-muted mb-3 italic">
        Calculated deterministically by backend RiskEngine v1.0 based on findings, validation state, exposure, and environment factors.
      </p>

      {factors.length === 0 ? (
        <p className="text-xs text-muted">No individual risk factors recorded for this finding.</p>
      ) : (
        <div className="space-y-2">
          {factors.map((factor, idx) => (
            <div key={idx} className="flex items-center justify-between text-xs p-2 rounded" style={{ background: "rgba(255,255,255,0.02)" }}>
              <div>
                <span className="font-mono font-semibold text-cyan-400 mr-2">[{factor.code}]</span>
                <span style={{ color: "var(--text-secondary)" }}>{factor.description}</span>
              </div>
              <span className="font-mono font-bold" style={{ color: factor.weight >= 0 ? "var(--accent-red)" : "var(--accent-green)" }}>
                {factor.weight >= 0 ? `+${factor.weight}` : factor.weight}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
