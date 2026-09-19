"use client";

import { useEffect, useState } from "react";
import { FindingEvidence, SecurityFinding, StatusHistory, getFindingEvidence, getFindingHistory } from "@/lib/security-api";
import { RiskBreakdown } from "./RiskBreakdown";
import { EvidenceTimeline } from "./EvidenceTimeline";
import { LifecycleTimeline } from "./LifecycleTimeline";
import { GovernanceActions } from "./GovernanceActions";

interface Props {
  finding: SecurityFinding | null;
  isAdmin: boolean;
  onClose: () => void;
  onRefreshFinding: () => void;
}

export function FindingDetailDrawer({
  finding,
  isAdmin,
  onClose,
  onRefreshFinding,
}: Props) {
  const [evidences, setEvidences] = useState<FindingEvidence[]>([]);
  const [history, setHistory] = useState<StatusHistory[]>([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);

  useEffect(() => {
    if (!finding) return;

    async function loadDetails() {
      if (!finding) return;
      setLoadingEvidence(true);
      setLoadingHistory(true);

      const [evData, histData] = await Promise.all([
        getFindingEvidence(finding.id),
        getFindingHistory(finding.id),
      ]);

      setEvidences(evData);
      setHistory(histData);
      setLoadingEvidence(false);
      setLoadingHistory(false);
    }

    loadDetails();
  }, [finding]);

  if (!finding) return null;

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
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm fade-in">
      <div className="w-full max-w-2xl h-full bg-slate-950 border-l border-slate-800 p-6 overflow-y-auto flex flex-col shadow-2xl">
        {/* Drawer Header */}
        <div className="flex items-start justify-between border-b pb-4 mb-4" style={{ borderColor: "var(--border-subtle)" }}>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs px-2 py-0.5 rounded font-bold uppercase"
                style={{ background: `${severityColor(finding.severity)}20`, color: severityColor(finding.severity) }}>
                {finding.severity}
              </span>
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-purple-950 text-purple-300 border border-purple-800">
                {finding.status}
              </span>
              <span className="text-xs text-muted font-mono">v{finding.lifecycleVersion}</span>
            </div>
            <h3 className="text-lg font-bold" style={{ fontFamily: "Outfit, sans-serif" }}>
              {finding.title}
            </h3>
            <p className="text-xs text-muted mt-1">
              FindingType: <span className="text-cyan-400 font-mono">{finding.findingType}</span>
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded text-muted hover:text-white hover:bg-slate-800 text-lg"
          >
            ✕
          </button>
        </div>

        {/* Description & Metadata */}
        <div className="glass-card p-4 mb-4">
          <p className="text-xs text-secondary leading-relaxed mb-3">{finding.description}</p>
          <div className="grid grid-cols-2 gap-2 text-[11px] text-muted border-t pt-2" style={{ borderColor: "var(--border-subtle)" }}>
            <div>
              <span className="block text-[10px] uppercase font-semibold">Fingerprint:</span>
              <code className="font-mono text-cyan-300 text-[10px] break-all">{finding.findingFingerprint}</code>
            </div>
            <div>
              <span className="block text-[10px] uppercase font-semibold">Repository ID:</span>
              <code className="font-mono text-cyan-300 text-[10px] break-all">{finding.repositoryId}</code>
            </div>
            <div>
              <span className="block text-[10px] uppercase font-semibold">First Observed:</span>
              <span>{new Date(finding.firstObservedAtUtc).toLocaleString()}</span>
            </div>
            <div>
              <span className="block text-[10px] uppercase font-semibold">Last Observed:</span>
              <span>{new Date(finding.lastObservedAtUtc).toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* Deterministic Risk Breakdown */}
        <RiskBreakdown
          riskScore={finding.riskScore}
          severity={finding.severity}
          factorBreakdownJson={finding.riskFactorBreakdownJson}
        />

        {/* Evidence Timeline */}
        <EvidenceTimeline evidences={evidences} loading={loadingEvidence} />

        {/* Lifecycle Governance History */}
        <LifecycleTimeline history={history} loading={loadingHistory} />

        {/* Admin Governance Actions */}
        <GovernanceActions
          findingId={finding.id}
          lifecycleVersion={finding.lifecycleVersion}
          isAdmin={isAdmin}
          onStatusUpdated={() => {
            onRefreshFinding();
          }}
        />
      </div>
    </div>
  );
}
