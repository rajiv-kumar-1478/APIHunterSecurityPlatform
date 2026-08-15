"use client";

import { FindingEvidence } from "@/lib/security-api";

interface Props {
  evidences: FindingEvidence[];
  loading: boolean;
}

export function EvidenceTimeline({ evidences, loading }: Props) {
  if (loading) {
    return <div className="text-xs text-muted py-4 text-center">Loading evidence timeline…</div>;
  }

  if (evidences.length === 0) {
    return <div className="text-xs text-muted py-4 text-center">No evidence records attached to this finding.</div>;
  }

  return (
    <div className="glass-card p-4 mb-4">
      <h4 className="text-sm font-semibold mb-3 flex items-center gap-2 border-b pb-2" style={{ borderColor: "var(--border-subtle)" }}>
        <span>🔍</span> Evidence Timeline ({evidences.length})
      </h4>

      <div className="space-y-3 relative pl-4 border-l" style={{ borderColor: "var(--border-subtle)" }}>
        {evidences.map((ev) => (
          <div key={ev.id} className="relative group">
            {/* Timeline bullet */}
            <div className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-500 border border-background" />

            <div className="p-3 rounded border text-xs" style={{ background: "rgba(255,255,255,0.02)", borderColor: "var(--border-subtle)" }}>
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800">
                  {ev.evidenceType}
                </span>
                <span className="text-[10px] text-muted">
                  {new Date(ev.createdAtUtc).toLocaleString()}
                </span>
              </div>

              <p className="font-medium text-foreground mb-1">
                Source: <span className="text-cyan-300">{ev.discoverySource}</span> — {ev.evidenceReference}
              </p>

              {ev.safeEvidenceJson && ev.safeEvidenceJson !== "{}" && (
                <details className="mt-2 text-[11px]">
                  <summary className="cursor-pointer text-muted hover:text-cyan-400 font-mono">
                    View Safe Evidence Payload
                  </summary>
                  <pre className="mt-1 p-2 rounded bg-black/40 text-gray-300 font-mono overflow-x-auto text-[10px]">
                    {ev.safeEvidenceJson}
                  </pre>
                </details>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
