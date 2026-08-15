"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

interface CandidateItem {
  id: string;
  maskedValue: string;
  credentialType: string;
  status: string; // CandidateStatus (Detected, Triaged, Resolved)
  firstDetectedAtUtc: string;
  lastDetectedAtUtc: string;
  totalOccurrences: number;
  latestValidationStatus?: string | null;
  latestValidationConfidence?: string | null;
  latestValidatedAtUtc?: string | null;
  latestValidationClassification?: string | null;
}

interface ValidationHistoryItem {
  id: string;
  candidateId: string;
  providerName: string;
  status: string;
  confidence: string;
  validatorVersion: string;
  policyVersion: string;
  responseClassification: string;
  safeEvidenceJson: string;
  latencyMs: number;

  httpStatusCode: number | null;
  validationAttemptNumber: number;
  validatedAtUtc: string;
}

export default function CredentialsPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; userId: string; email?: string } | null>(null);
  const [candidates, setCandidates] = useState<CandidateItem[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  // Filter States
  const [providerFilter, setProviderFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  // History & Graph Modal State
  const [selectedCandidate, setSelectedCandidate] = useState<CandidateItem | null>(null);
  const [history, setHistory] = useState<ValidationHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [validatingCandidateId, setValidatingCandidateId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  useEffect(() => {
    async function init() {
      try {
        const res = await fetch(`${API_URL}/api/v1/auth/me`, { credentials: "include" });
        if (!res.ok) {
          router.replace("/login");
          return;
        }
        const uData = await res.json();
        setUser(uData);

        await fetchCandidates();
      } catch {
        router.replace("/login");
      } finally {
        setLoading(false);
      }
    }
    init();
  }, [router, page, providerFilter, statusFilter]);

  async function fetchCandidates() {
    setLoading(true);
    try {
      let url = `${API_URL}/api/v1/candidates?page=${page}&pageSize=15`;
      if (providerFilter !== "all") url += `&credentialType=${encodeURIComponent(providerFilter)}`;

      const res = await fetch(url, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        let items: CandidateItem[] = data.items ?? [];

        // Apply client-side status filter if specified
        if (statusFilter !== "all") {
          items = items.filter(c => (c.latestValidationStatus ?? "Unvalidated").toLowerCase() === statusFilter.toLowerCase());
        }

        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          items = items.filter(c => c.maskedValue.toLowerCase().includes(q) || c.credentialType.toLowerCase().includes(q));
        }

        setCandidates(items);
        setTotalCount(data.totalCount ?? items.length);
      }
    } catch (e) {
      console.error("Failed to fetch candidates", e);
    } finally {
      setLoading(false);
    }
  }

  async function handleTriggerValidation(candidateId: string) {
    setValidatingCandidateId(candidateId);
    setActionMessage(null);
    try {
      const res = await fetch(`${API_URL}/api/v1/validation/candidates/${candidateId}/validate`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" }
      });

      if (res.ok) {
        const result = await res.json();
        setActionMessage({ type: "success", text: `Validation Completed! Status: ${result.status}` });
        await fetchCandidates();
        if (selectedCandidate?.id === candidateId) {
          await openHistoryModal(selectedCandidate);
        }
      } else {
        const err = await res.json();
        setActionMessage({ type: "error", text: err.message ?? "Validation request failed" });
      }
    } catch (e) {
      setActionMessage({ type: "error", text: "Network error triggering validation" });
    } finally {
      setValidatingCandidateId(null);
    }
  }

  async function openHistoryModal(cand: CandidateItem) {
    setSelectedCandidate(cand);
    setHistoryLoading(true);
    setHistory([]);
    try {
      const res = await fetch(`${API_URL}/api/v1/validation/candidates/${cand.id}/history`, {
        credentials: "include"
      });
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (e) {
      console.error("Failed to fetch validation history", e);
    } finally {
      setHistoryLoading(false);
    }
  }

  function renderValidationBadge(status?: string | null) {
    if (!status) {
      return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-slate-800 text-slate-400 border border-slate-700">Unvalidated</span>;
    }

    switch (status) {
      case "Valid":
      case "ValidInsufficientScope":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-500/40 shadow-sm shadow-emerald-500/20">🟢 {status}</span>;
      case "Invalid":
      case "Expired":
      case "Revoked":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-rose-950/80 text-rose-400 border border-rose-500/40 shadow-sm shadow-rose-500/20">🔴 {status}</span>;
      case "RateLimited":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-amber-950/80 text-amber-400 border border-amber-500/40 shadow-sm shadow-amber-500/20">🟡 Rate Limited</span>;
      case "Unsupported":
      case "BlockedByPolicy":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-sky-950/80 text-sky-400 border border-sky-500/40 shadow-sm shadow-sky-500/20">🔵 {status}</span>;
      case "Unavailable":
      case "ValidationError":
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-purple-950/80 text-purple-400 border border-purple-500/40 shadow-sm shadow-purple-500/20">🟣 {status}</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-slate-800 text-slate-300 border border-slate-700">{status}</span>;
    }
  }

  function renderProvenancePill(type: string) {
    return (
      <div className="flex flex-wrap gap-1">
        <span className="px-2 py-0.5 text-[10px] font-medium rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60">⚙️ Deterministic</span>
        <span className="px-2 py-0.5 text-[10px] font-medium rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">⚡ Validation</span>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100 font-sans antialiased">
      <Sidebar isAdmin={user?.isPlatformAdmin ?? false} userEmail={user?.email} />

      <main className="flex-1 p-8 max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div>
            <h1 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
              <span>🔐 Security Credentials & Validation Intelligence</span>
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Live credential candidate inventory with server-side SSRF validation, historical audit trail, and security graph provenance.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs px-3 py-1.5 rounded-md bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono">
              Zero Raw Secret Disclosure Verified
            </span>
          </div>
        </div>

        {/* Global Action Message */}
        {actionMessage && (
          <div className={`p-4 rounded-lg border text-sm font-medium ${actionMessage.type === "success" ? "bg-emerald-950/90 text-emerald-200 border-emerald-700" : "bg-rose-950/90 text-rose-200 border-rose-700"}`}>
            {actionMessage.text}
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800/80 shadow-lg">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Candidates</p>
            <p className="text-3xl font-bold text-white mt-2">{totalCount}</p>
            <p className="text-xs text-slate-500 mt-1">Discovery & Triage inventory</p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900/90 border border-emerald-900/40 shadow-lg">
            <p className="text-xs font-semibold uppercase tracking-wider text-emerald-400">Active Valid Credentials</p>
            <p className="text-3xl font-bold text-emerald-400 mt-2">
              {candidates.filter(c => c.latestValidationStatus === "Valid" || c.latestValidationStatus === "ValidInsufficientScope").length}
            </p>
            <p className="text-xs text-emerald-500/80 mt-1">Verified live access</p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900/90 border border-rose-900/40 shadow-lg">
            <p className="text-xs font-semibold uppercase tracking-wider text-rose-400">Invalid / Revoked</p>
            <p className="text-3xl font-bold text-rose-400 mt-2">
              {candidates.filter(c => ["Invalid", "Expired", "Revoked"].includes(c.latestValidationStatus ?? "")).length}
            </p>
            <p className="text-xs text-rose-500/80 mt-1">Inactive / Revoked keys</p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900/90 border border-sky-900/40 shadow-lg">
            <p className="text-xs font-semibold uppercase tracking-wider text-sky-400">RateLimited / Unsupported</p>
            <p className="text-3xl font-bold text-sky-400 mt-2">
              {candidates.filter(c => ["RateLimited", "Unsupported", "BlockedByPolicy"].includes(c.latestValidationStatus ?? "")).length}
            </p>
            <p className="text-xs text-sky-500/80 mt-1">Safe non-invalid states</p>
          </div>
        </div>

        {/* Toolbar & Filters */}
        <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-slate-900/60 p-4 rounded-xl border border-slate-800">
          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
            {/* Search Input */}
            <input
              type="text"
              placeholder="Search candidate (masked key or type)..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="px-3.5 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-full sm:w-64"
            />

            {/* Provider Filter */}
            <select
              value={providerFilter}
              onChange={e => setProviderFilter(e.target.value)}
              className="px-3.5 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="all">All Providers</option>
              <option value="OpenAI">OpenAI</option>
              <option value="Anthropic">Anthropic</option>
              <option value="GitHub">GitHub</option>
              <option value="AWS STS">AWS STS</option>
              <option value="Stripe">Stripe</option>
              <option value="SendGrid">SendGrid</option>
              <option value="Mailgun">Mailgun</option>
              <option value="DeepSeek">DeepSeek</option>
              <option value="Groq">Groq</option>
              <option value="Slack">Slack</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="px-3.5 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="all">All Validation Statuses</option>
              <option value="valid">Valid</option>
              <option value="invalid">Invalid</option>
              <option value="revoked">Revoked</option>
              <option value="ratelimited">RateLimited</option>
              <option value="unsupported">Unsupported</option>
              <option value="unvalidated">Unvalidated</option>
            </select>
          </div>

          <button
            onClick={() => fetchCandidates()}
            className="px-4 py-2 text-sm font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition"
          >
            🔄 Refresh Candidates
          </button>
        </div>

        {/* Candidates Table */}
        <div className="bg-slate-900/90 rounded-xl border border-slate-800/80 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/80 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-4">Masked Credential</th>
                  <th className="px-6 py-4">Provider</th>
                  <th className="px-6 py-4">Discovery Provenance</th>
                  <th className="px-6 py-4">Validation Truth</th>
                  <th className="px-6 py-4">Confidence</th>
                  <th className="px-6 py-4">Last Validated</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {loading ? (
                  <tr>
                    <td colSpan={7} className="px-6 py-12 text-center text-slate-500">
                      Loading credential candidates...
                    </td>
                  </tr>
                ) : candidates.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-6 py-12 text-center text-slate-500">
                      No credential candidates found matching filter criteria.
                    </td>
                  </tr>
                ) : (
                  candidates.map(cand => (
                    <tr key={cand.id} className="hover:bg-slate-800/40 transition">
                      {/* Masked Value ONLY */}
                      <td className="px-6 py-4 font-mono text-sm text-slate-100 font-semibold">
                        {cand.maskedValue}
                      </td>

                      {/* Provider */}
                      <td className="px-6 py-4 font-medium text-slate-200">
                        {cand.credentialType}
                      </td>

                      {/* Discovery Provenance */}
                      <td className="px-6 py-4">
                        {renderProvenancePill(cand.credentialType)}
                      </td>

                      {/* Validation Truth */}
                      <td className="px-6 py-4">
                        {renderValidationBadge(cand.latestValidationStatus)}
                      </td>

                      {/* Confidence */}
                      <td className="px-6 py-4 text-xs font-medium text-slate-400">
                        {cand.latestValidationConfidence ? (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {cand.latestValidationConfidence}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>

                      {/* Last Validated */}
                      <td className="px-6 py-4 text-xs text-slate-400">
                        {cand.latestValidatedAtUtc ? (
                          new Date(cand.latestValidatedAtUtc).toLocaleString()
                        ) : (
                          <span className="text-slate-600">Never</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-6 py-4 text-right space-x-2">
                        <button
                          onClick={() => openHistoryModal(cand)}
                          className="px-3 py-1.5 text-xs font-semibold rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                        >
                          📜 Audit History
                        </button>

                        {user?.isPlatformAdmin && (
                          <button
                            disabled={validatingCandidateId === cand.id}
                            onClick={() => handleTriggerValidation(cand.id)}
                            className="px-3 py-1.5 text-xs font-semibold rounded bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white shadow-sm shadow-indigo-500/20 transition"
                          >
                            {validatingCandidateId === cand.id ? "Validating..." : "⚡ Validate Now"}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between px-6 py-4 bg-slate-950/60 border-t border-slate-800 text-xs text-slate-400">
            <span>
              Showing Page <strong>{page}</strong> of <strong>{Math.ceil(totalCount / 15) || 1}</strong> ({totalCount} total)
            </span>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300"
              >
                Previous
              </button>
              <button
                disabled={page * 15 >= totalCount}
                onClick={() => setPage(p => p + 1)}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        {/* Validation History & Security Graph Modal */}
        {selectedCandidate && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
              {/* Modal Header */}
              <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-3">
                    <span>Validation Audit Trail & Security Graph</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5 font-mono">
                    Candidate #{selectedCandidate.id} — {selectedCandidate.credentialType} ({selectedCandidate.maskedValue})
                  </p>
                </div>
                <button
                  onClick={() => setSelectedCandidate(null)}
                  className="text-slate-400 hover:text-white text-lg font-bold p-1 rounded-lg hover:bg-slate-800"
                >
                  ✕
                </button>
              </div>

              {/* Modal Content */}
              <div className="p-6 overflow-y-auto space-y-6 flex-1">
                {/* Security Intelligence Graph Relationship Card */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                    <span>🕸️ Security Intelligence Graph Topology</span>
                  </h3>
                  <div className="flex items-center gap-3 text-xs text-slate-300 overflow-x-auto py-2">
                    <span className="px-3 py-2 rounded-lg bg-indigo-950 border border-indigo-800 text-indigo-300 font-mono font-medium">
                      CredentialNode ({selectedCandidate.maskedValue})
                    </span>
                    <span className="text-slate-500 font-mono">──[AppearsIn]──▶</span>
                    <span className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 font-mono">
                      RepositoryNode
                    </span>
                    <span className="text-slate-500 font-mono">──[AssociatedWith]──▶</span>
                    <span className="px-3 py-2 rounded-lg bg-emerald-950 border border-emerald-800 text-emerald-300 font-mono">
                      Service / Environment
                    </span>
                  </div>
                </div>

                {/* Historical Timeline */}
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                    Historical Validation Attempts (Append-Only)
                  </h3>

                  {historyLoading ? (
                    <div className="text-center py-8 text-slate-500 text-sm">Loading validation history...</div>
                  ) : history.length === 0 ? (
                    <div className="text-center py-8 text-slate-500 text-sm">No historical validation attempts recorded.</div>
                  ) : (
                    <div className="space-y-3">
                      {history.map(item => (
                        <div key={item.id} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col sm:flex-row justify-between gap-4">
                          <div className="space-y-1">
                            <div className="flex items-center gap-3">
                              <span className="text-xs font-mono text-slate-400">Attempt #{item.validationAttemptNumber}</span>
                              {renderValidationBadge(item.status)}
                              <span className="text-xs font-medium text-slate-400">Confidence: {item.confidence}</span>
                            </div>
                            <p className="text-xs text-slate-300 font-mono mt-1">
                              Classification: <span className="text-slate-100">{item.responseClassification}</span>
                            </p>
                            {item.safeEvidenceJson && (
                              <pre className="text-[11px] font-mono text-slate-400 bg-slate-900 p-2 rounded border border-slate-800/80 mt-1 max-h-24 overflow-y-auto">
                                {item.safeEvidenceJson}
                              </pre>
                            )}
                          </div>

                          <div className="text-right text-xs text-slate-400 space-y-1 sm:self-center">
                            <p>Latency: <strong className="text-slate-200">{item.latencyMs} ms</strong></p>
                            <p>HTTP: <strong className="text-slate-200">{item.httpStatusCode ?? "N/A"}</strong></p>
                            <p className="text-[11px] text-slate-500">{new Date(item.validatedAtUtc).toLocaleString()}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Modal Footer */}
              <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex justify-between items-center">
                <span className="text-xs text-slate-500">
                  Discovery lifecycle (CandidateStatus) is preserved separately from validation truth.
                </span>
                <button
                  onClick={() => setSelectedCandidate(null)}
                  className="px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
