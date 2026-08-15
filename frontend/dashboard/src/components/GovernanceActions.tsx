"use client";

import { useState } from "react";
import { updateFindingStatus } from "@/lib/security-api";

interface Props {
  findingId: string;
  currentStatus: string;
  lifecycleVersion: number;
  isAdmin: boolean;
  onStatusUpdated: () => void;
}

export function GovernanceActions({
  findingId,
  currentStatus,
  lifecycleVersion,
  isAdmin,
  onStatusUpdated,
}: Props) {
  const [newStatus, setNewStatus] = useState<string>("Confirmed");
  const [reason, setReason] = useState<string>("");
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  if (!isAdmin) {
    return (
      <div className="glass-card p-4 text-xs text-muted">
        🔒 Finding governance actions are restricted to Platform Administrators and users with <code>finding.manage</code> permission.
      </div>
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!reason.trim()) {
      setMessage({ text: "Mandatory reason text is required for status transitions.", error: true });
      return;
    }

    setSubmitting(true);
    setMessage(null);

    const res = await updateFindingStatus(findingId, newStatus, lifecycleVersion, reason.trim());
    setSubmitting(false);

    if (res.success) {
      setMessage({ text: res.message, error: false });
      setReason("");
      onStatusUpdated();
    } else {
      setMessage({ text: res.message, error: true });
    }
  }

  return (
    <div className="glass-card p-4 border-t-2" style={{ borderTopColor: "var(--accent-purple)" }}>
      <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
        <span>🛡️</span> Admin Governance Status Transition
      </h4>

      <p className="text-xs text-muted mb-3">
        Transition finding state. Concurrency Version Guard: <code className="text-cyan-400">v{lifecycleVersion}</code>
      </p>

      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1 font-medium">New Status:</label>
          <select
            value={newStatus}
            onChange={(e) => setNewStatus(e.target.value)}
            disabled={submitting}
            className="w-full px-3 py-1.5 text-xs rounded border bg-background text-foreground"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <option value="Confirmed">Confirmed</option>
            <option value="Remediated">Remediated</option>
            <option value="AcceptedRisk">Accepted Risk</option>
            <option value="FalsePositive">False Positive</option>
            <option value="Resolved">Resolved (Requires Resolution Reason)</option>
            <option value="Open">Re-open (Set Status to Open)</option>
          </select>
        </div>

        <div>
          <label className="block text-xs text-muted mb-1 font-medium">
            Mandatory Governance Reason:
          </label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={submitting}
            placeholder="Explain why this finding status is being transitioned (e.g. Credential rotated in commit xyz)..."
            rows={2}
            className="w-full p-2 text-xs rounded border bg-background text-foreground"
            style={{ borderColor: "var(--border-subtle)" }}
          />
        </div>

        {message && (
          <div className={`p-2 rounded text-xs ${message.error ? "bg-red-950/60 text-red-300 border border-red-800" : "bg-green-950/60 text-green-300 border border-green-800"}`}>
            {message.text}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting || !reason.trim()}
          className="px-4 py-1.5 text-xs rounded font-semibold text-white transition-opacity disabled:opacity-50"
          style={{ background: "var(--accent-purple)" }}
        >
          {submitting ? "Transitioning…" : "Execute Status Transition"}
        </button>
      </form>
    </div>
  );
}
