"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
import { ApiError, apiRequest, getErrorMessage } from "@/lib/api-client";

interface CandidateListResponse {
  items?: CandidateItem[];
  totalCount?: number;
}

interface ValidationResult {
  status: string;
}

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

  // Azure OpenAI Tenant Configuration
  const [azureEndpoint, setAzureEndpoint] = useState("");
  const [azureApiVersion, setAzureApiVersion] = useState("2023-05-15");
  const [azureEnabled, setAzureEnabled] = useState(true);
  const [azureUpdatedAt, setAzureUpdatedAt] = useState<string | null>(null);
  const [showAzureConfig, setShowAzureConfig] = useState(false);
  const [azureSaving, setAzureSaving] = useState(false);
  const [azureConfigMessage, setAzureConfigMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const requestCandidates = useCallback(async () => {
    const query = new URLSearchParams({
      page: String(page),
      pageSize: "15",
    });
    if (providerFilter !== "all") query.set("credentialType", providerFilter);

    const data = await apiRequest<CandidateListResponse>(`/api/v1/candidates?${query.toString()}`);
    let items = data.items ?? [];

    // Apply client-side status filter if specified
    if (statusFilter !== "all") {
      items = items.filter(
        (candidate) =>
          (candidate.latestValidationStatus ?? "Unvalidated").toLowerCase() === statusFilter.toLowerCase(),
      );
    }

    if (searchQuery.trim()) {
      const queryText = searchQuery.toLowerCase();
      items = items.filter(
        (candidate) =>
          candidate.maskedValue.toLowerCase().includes(queryText) ||
          candidate.credentialType.toLowerCase().includes(queryText),
      );
    }

    return { items, totalCount: data.totalCount ?? items.length };
  }, [page, providerFilter, searchQuery, statusFilter]);

  const fetchCandidates = useCallback(async () => {
    try {
      const data = await requestCandidates();
      setCandidates(data.items);
      setTotalCount(data.totalCount);
    } catch (error: unknown) {
      console.error("Failed to fetch candidates", error);
    } finally {
      setLoading(false);
    }
  }, [requestCandidates]);

  useEffect(() => {
    async function loadCurrentUser() {
      try {
        const userData = await apiRequest<{
          isPlatformAdmin: boolean;
          userId: string;
          email?: string;
        }>("/api/v1/auth/me");
        setUser(userData);
      } catch {
        router.replace("/login");
      }
    }
    void loadCurrentUser();
  }, [router]);

  useEffect(() => {
    async function loadAzureConfig() {
      try {
        const config = await apiRequest<{
          providerName: string;
          resourceEndpointUrl: string;
          apiVersion: string;
          isEnabled: boolean;
          updatedAtUtc: string | null;
        }>("/api/v1/settings/providers/azure-openai");
        if (config?.resourceEndpointUrl) {
          setAzureEndpoint(config.resourceEndpointUrl);
          setAzureApiVersion(config.apiVersion || "2023-05-15");
          setAzureEnabled(config.isEnabled);
          setAzureUpdatedAt(config.updatedAtUtc);
        }
      } catch {
        // Not configured yet
      }
    }
    void loadAzureConfig();
  }, []);

  useEffect(() => {
    if (!user) return;

    let cancelled = false;
    void requestCandidates()
      .then((data) => {
        if (cancelled) return;
        setCandidates(data.items);
        setTotalCount(data.totalCount);
      })
      .catch((error: unknown) => {
        if (!cancelled) console.error("Failed to fetch candidates", error);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [requestCandidates, user]);

  async function handleTriggerValidation(candidateId: string) {
    setValidatingCandidateId(candidateId);
    setActionMessage(null);
    try {
      const result = await apiRequest<ValidationResult>(
        `/api/v1/validation/candidates/${candidateId}/validate`,
        { method: "POST" },
      );
      setActionMessage({ type: "success", text: `Validation Completed! Status: ${result.status}` });
      await fetchCandidates();
      if (selectedCandidate?.id === candidateId) {
        await openHistoryModal(selectedCandidate);
      }
    } catch (error: unknown) {
      setActionMessage({
        type: "error",
        text: error instanceof ApiError ? error.message : "Network error triggering validation",
      });
    } finally {
      setValidatingCandidateId(null);
    }
  }

  async function openHistoryModal(cand: CandidateItem) {
    setSelectedCandidate(cand);
    setHistoryLoading(true);
    setHistory([]);
    try {
      const data = await apiRequest<ValidationHistoryItem[]>(
        `/api/v1/validation/candidates/${cand.id}/history`,
      );
      setHistory(data);
    } catch (error: unknown) {
      console.error("Failed to fetch validation history", error);
    } finally {
      setHistoryLoading(false);
    }
  }

  function renderValidationBadge(status?: string | null) {
    if (!status) {
      return <span className="badge badge-[#4a6580] bg-white/5 border border-white/10">Unvalidated</span>;
    }

    switch (status) {
      case "Valid":
      case "ValidInsufficientScope":
        return <span className="badge badge-healthy text-[10px]">🟢 {status}</span>;
      case "Invalid":
      case "Expired":
      case "Revoked":
        return <span className="badge badge-unhealthy text-[10px]">🔴 {status}</span>;
      case "RateLimited":
        return <span className="badge badge-degraded text-[10px]">🟡 Rate Limited</span>;
      case "Unsupported":
      case "BlockedByPolicy":
        return <span className="badge badge-admin text-[10px]">🔵 {status}</span>;
      case "Unavailable":
      case "ValidationError":
        return <span className="badge badge-admin text-[10px]">🟣 {status}</span>;
      default:
        return <span className="badge badge-[#4a6580] bg-white/5 border border-white/10">{status}</span>;
    }
  }

  function renderProvenancePill() {
    return (
      <div className="flex flex-wrap gap-1">
        <span className="px-2 py-0.5 text-[10px] font-semibold rounded bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/20">⚙️ Deterministic</span>
        <span className="px-2 py-0.5 text-[10px] font-semibold rounded bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20">⚡ Validation</span>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-[#7ba3c8] font-medium">Loading Credential Intelligence…</p>
        </div>
      </div>
    );
  }

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="Credentials & Validation Intelligence"
      subtitle="Live candidate secret inventory with SSRF active validation, history audit trail & security graph provenance"
      actions={
        <span className="px-3 py-1.5 rounded-lg bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/30 font-mono text-[11px] font-semibold">
          Zero Raw Secret Disclosure Verified
        </span>
      }
    >
      {/* Global Action Message */}
      {actionMessage && (
        <div className={`p-4 rounded-xl border text-xs font-semibold fade-in ${actionMessage.type === "success" ? "bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/30" : "bg-[#ff4757]/10 text-[#ff4757] border-[#ff4757]/30"}`}>
          {actionMessage.text}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 fade-in">
        <div className="glass-card p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#4a6580]">Total Candidates</p>
          <p className="text-3xl font-bold text-[#e8f4ff] mt-2" style={{ fontFamily: "Outfit, sans-serif" }}>{totalCount}</p>
          <p className="text-xs text-[#7ba3c8] mt-1">Discovery & Triage inventory</p>
        </div>
        <div className="glass-card p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#00ff88]">Active Valid Credentials</p>
          <p className="text-3xl font-bold text-[#00ff88] mt-2" style={{ fontFamily: "Outfit, sans-serif" }}>
            {candidates.filter(c => c.latestValidationStatus === "Valid" || c.latestValidationStatus === "ValidInsufficientScope").length}
          </p>
          <p className="text-xs text-[#7ba3c8] mt-1">Verified live access</p>
        </div>
        <div className="glass-card p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#ff4757]">Invalid / Revoked</p>
          <p className="text-3xl font-bold text-[#ff4757] mt-2" style={{ fontFamily: "Outfit, sans-serif" }}>
            {candidates.filter(c => ["Invalid", "Expired", "Revoked"].includes(c.latestValidationStatus ?? "")).length}
          </p>
          <p className="text-xs text-[#7ba3c8] mt-1">Inactive / Revoked keys</p>
        </div>
        <div className="glass-card p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#00d4ff]">RateLimited / Unsupported</p>
          <p className="text-3xl font-bold text-[#00d4ff] mt-2" style={{ fontFamily: "Outfit, sans-serif" }}>
            {candidates.filter(c => ["RateLimited", "Unsupported", "BlockedByPolicy"].includes(c.latestValidationStatus ?? "")).length}
          </p>
          <p className="text-xs text-[#7ba3c8] mt-1">Safe non-invalid states</p>
        </div>
      </div>

      {/* Azure OpenAI Resource Endpoint Configuration Card */}
      <div className="glass-card p-5 fade-in">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#00d4ff]" />
              <h3 className="text-xs font-bold text-[#e8f4ff] uppercase tracking-wider" style={{ fontFamily: "Outfit, sans-serif" }}>
                Azure OpenAI Tenant Resource Endpoint
              </h3>
              {azureEndpoint ? (
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#00ff88]/20 text-[#00ff88] font-semibold border border-[#00ff88]/30">
                  Configured
                </span>
              ) : (
                <span className="text-[10px] px-2 py-0.5 rounded bg-white/5 text-[#7ba3c8] font-medium border border-white/10">
                  Unconfigured
                </span>
              )}
            </div>
            <p className="text-xs text-[#7ba3c8] mt-1">
              Azure OpenAI credentials require a per-tenant resource endpoint (<code className="text-[#00d4ff]">https://&#123;resource&#125;.openai.azure.com</code>).
            </p>
          </div>
          <button
            onClick={() => setShowAzureConfig(!showAzureConfig)}
            className="btn-secondary text-xs"
          >
            {showAzureConfig ? "Hide Settings" : azureEndpoint ? "Edit Endpoint" : "Configure Endpoint"}
          </button>
        </div>

        {showAzureConfig && (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setAzureSaving(true);
              setAzureConfigMessage(null);
              try {
                const updated = await apiRequest<{
                  providerName: string;
                  resourceEndpointUrl: string;
                  apiVersion: string;
                  isEnabled: boolean;
                  updatedAtUtc: string | null;
                }>("/api/v1/settings/providers/azure-openai", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({
                    resourceEndpointUrl: azureEndpoint.trim(),
                    apiVersion: azureApiVersion.trim() || "2023-05-15",
                    isEnabled: azureEnabled,
                  }),
                });
                setAzureEndpoint(updated.resourceEndpointUrl);
                setAzureApiVersion(updated.apiVersion);
                setAzureEnabled(updated.isEnabled);
                setAzureUpdatedAt(updated.updatedAtUtc);
                setAzureConfigMessage({
                  type: "success",
                  text: "Azure OpenAI endpoint saved and SSRF DNS screening passed.",
                });
              } catch (err: unknown) {
                setAzureConfigMessage({
                  type: "error",
                  text: getErrorMessage(err, "Failed to save Azure OpenAI endpoint."),
                });
              } finally {
                setAzureSaving(false);
              }
            }}
            className="mt-4 pt-4 border-t border-[#00d4ff]/10 space-y-4"
          >
            {azureConfigMessage && (
              <div
                className={`text-xs p-3 rounded-xl border ${
                  azureConfigMessage.type === "success"
                    ? "bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]"
                    : "bg-[#ff4757]/10 border-[#ff4757]/30 text-[#ff4757]"
                }`}
              >
                {azureConfigMessage.text}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2">
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">
                  Resource Endpoint URL (must end with .openai.azure.com or .openai.azure.us) *
                </label>
                <input
                  type="url"
                  required
                  placeholder="https://my-company.openai.azure.com"
                  value={azureEndpoint}
                  onChange={(e) => setAzureEndpoint(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">
                  API Version
                </label>
                <input
                  type="text"
                  placeholder="2023-05-15"
                  value={azureApiVersion}
                  onChange={(e) => setAzureApiVersion(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <label className="flex items-center gap-2 cursor-pointer text-xs text-[#7ba3c8]">
                <input
                  type="checkbox"
                  checked={azureEnabled}
                  onChange={(e) => setAzureEnabled(e.target.checked)}
                  className="rounded bg-[#080c14] border-[#00d4ff]/30 text-[#00d4ff] focus:ring-0"
                />
                Enable validation for Azure OpenAI credentials
              </label>

              <button
                type="submit"
                disabled={azureSaving || !azureEndpoint.trim()}
                className="btn-primary text-xs"
              >
                {azureSaving ? "Testing & Saving..." : "Save & Verify SSRF"}
              </button>
            </div>

            {azureUpdatedAt && (
              <p className="text-[11px] text-[#4a6580]">
                Last updated: {new Date(azureUpdatedAt).toLocaleString()}
              </p>
            )}
          </form>
        )}
      </div>

      {/* Toolbar & Filters */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center glass-card p-4 fade-in">
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          {/* Search Input */}
          <input
            type="text"
            placeholder="Search candidate (masked key or type)..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="px-3.5 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff] w-full sm:w-64"
          />

          {/* Provider Filter */}
          <select
            value={providerFilter}
            onChange={e => setProviderFilter(e.target.value)}
            className="px-3.5 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
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
            <option value="Cohere">Cohere</option>
            <option value="Slack">Slack</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="px-3.5 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
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
          className="btn-secondary text-xs"
        >
          🔄 Refresh Candidates
        </button>
      </div>

      {/* Candidates Table */}
      <div className="glass-card overflow-hidden fade-in">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[800px]">
            <thead>
              <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                <th className="p-4">Masked Credential</th>
                <th className="p-4">Provider</th>
                <th className="p-4">Discovery Provenance</th>
                <th className="p-4">Validation Truth</th>
                <th className="p-4">Confidence</th>
                <th className="p-4">Last Validated</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-[#7ba3c8]">
                    Loading credential candidates...
                  </td>
                </tr>
              ) : candidates.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-[#7ba3c8]">
                    No credential candidates found matching filter criteria.
                  </td>
                </tr>
              ) : (
                candidates.map(cand => (
                  <tr key={cand.id} className="hover:bg-white/[0.02] transition-colors">
                    {/* Masked Value ONLY */}
                    <td className="p-4 font-mono text-xs text-[#e8f4ff] font-semibold">
                      {cand.maskedValue}
                    </td>

                    {/* Provider */}
                    <td className="p-4 font-medium text-[#e8f4ff]">
                      {cand.credentialType}
                    </td>

                    {/* Discovery Provenance */}
                    <td className="p-4">
                      {renderProvenancePill()}
                    </td>

                    {/* Validation Truth */}
                    <td className="p-4">
                      {renderValidationBadge(cand.latestValidationStatus)}
                    </td>

                    {/* Confidence */}
                    <td className="p-4 text-xs font-medium text-[#7ba3c8]">
                      {cand.latestValidationConfidence ? (
                        <span className="px-2 py-0.5 rounded bg-white/5 text-[#e8f4ff] border border-white/10">
                          {cand.latestValidationConfidence}
                        </span>
                      ) : (
                        <span className="text-[#4a6580]">—</span>
                      )}
                    </td>

                    {/* Last Validated */}
                    <td className="p-4 text-xs text-[#7ba3c8]">
                      {cand.latestValidatedAtUtc ? (
                        new Date(cand.latestValidatedAtUtc).toLocaleString()
                      ) : (
                        <span className="text-[#4a6580]">Never</span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="p-4 text-right space-x-2">
                      <button
                        onClick={() => openHistoryModal(cand)}
                        className="btn-secondary text-xs"
                      >
                        📜 Audit History
                      </button>

                      {user?.isPlatformAdmin && (
                        <button
                          disabled={validatingCandidateId === cand.id}
                          onClick={() => handleTriggerValidation(cand.id)}
                          className="btn-primary text-xs"
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
        <div className="flex items-center justify-between p-4 border-t border-[#00d4ff]/10 text-xs text-[#7ba3c8] bg-white/[0.01]">
          <span>
            Showing Page <strong>{page}</strong> of <strong>{Math.ceil(totalCount / 15) || 1}</strong> ({totalCount} total)
          </span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              className="btn-secondary text-xs disabled:opacity-40"
            >
              Previous
            </button>
            <button
              disabled={page * 15 >= totalCount}
              onClick={() => setPage(p => p + 1)}
              className="btn-secondary text-xs disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Validation History & Security Graph Modal */}
      {selectedCandidate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md fade-in">
          <div className="glass-card max-w-4xl w-full max-h-[85vh] flex flex-col border-[#00d4ff]/30 overflow-hidden">
            {/* Modal Header */}
            <div className="p-6 border-b border-[#00d4ff]/10 flex items-center justify-between bg-white/[0.02]">
              <div>
                <h2 className="text-lg font-bold text-[#e8f4ff] flex items-center gap-3" style={{ fontFamily: "Outfit, sans-serif" }}>
                  <span>Validation Audit Trail & Security Graph</span>
                </h2>
                <p className="text-xs text-[#7ba3c8] mt-0.5 font-mono">
                  Candidate #{selectedCandidate.id} — {selectedCandidate.credentialType} ({selectedCandidate.maskedValue})
                </p>
              </div>
              <button
                onClick={() => setSelectedCandidate(null)}
                className="text-[#7ba3c8] hover:text-white text-lg font-bold p-1 rounded-lg hover:bg-white/5"
              >
                ✕
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-6 flex-1">
              {/* Security Intelligence Graph Relationship Card */}
              <div className="p-4 rounded-xl bg-[#080c14] border border-[#00d4ff]/20">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#4a6580] mb-3 flex items-center gap-2">
                  <span>🕸️ Security Intelligence Graph Topology</span>
                </h3>
                <div className="flex items-center gap-3 text-xs text-[#e8f4ff] overflow-x-auto py-2">
                  <span className="px-3 py-2 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff] font-mono font-medium">
                    CredentialNode ({selectedCandidate.maskedValue})
                  </span>
                  <span className="text-[#4a6580] font-mono">──[AppearsIn]──▶</span>
                  <span className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-[#e8f4ff] font-mono">
                    RepositoryNode
                  </span>
                  <span className="text-[#4a6580] font-mono">──[AssociatedWith]──▶</span>
                  <span className="px-3 py-2 rounded-xl bg-[#00ff88]/10 border border-[#00ff88]/30 text-[#00ff88] font-mono">
                    Service / Environment
                  </span>
                </div>
              </div>

              {/* Historical Timeline */}
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#4a6580] mb-3">
                  Historical Validation Attempts (Append-Only)
                </h3>

                {historyLoading ? (
                  <div className="text-center py-8 text-[#7ba3c8] text-xs">Loading validation history...</div>
                ) : history.length === 0 ? (
                  <div className="text-center py-8 text-[#7ba3c8] text-xs">No historical validation attempts recorded.</div>
                ) : (
                  <div className="space-y-3">
                    {history.map(item => (
                      <div key={item.id} className="p-4 rounded-xl bg-[#080c14]/80 border border-[#00d4ff]/10 flex flex-col sm:flex-row justify-between gap-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-3">
                            <span className="text-xs font-mono text-[#7ba3c8]">Attempt #{item.validationAttemptNumber}</span>
                            {renderValidationBadge(item.status)}
                            <span className="text-xs font-medium text-[#7ba3c8]">Confidence: {item.confidence}</span>
                          </div>
                          <p className="text-xs text-[#7ba3c8] font-mono mt-1">
                            Classification: <span className="text-[#e8f4ff]">{item.responseClassification}</span>
                          </p>
                          {item.safeEvidenceJson && (
                            <pre className="text-[11px] font-mono text-[#7ba3c8] bg-black/50 p-2.5 rounded-lg border border-[#00d4ff]/10 mt-1 max-h-24 overflow-y-auto">
                              {item.safeEvidenceJson}
                            </pre>
                          )}
                        </div>

                        <div className="text-right text-xs text-[#7ba3c8] space-y-1 sm:self-center">
                          <p>Latency: <strong className="text-[#e8f4ff]">{item.latencyMs} ms</strong></p>
                          <p>HTTP: <strong className="text-[#e8f4ff]">{item.httpStatusCode ?? "N/A"}</strong></p>
                          <p className="text-[11px] text-[#4a6580]">{new Date(item.validatedAtUtc).toLocaleString()}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[#00d4ff]/10 bg-white/[0.02] flex flex-wrap justify-between items-center gap-3">
              <span className="text-xs text-[#4a6580]">
                Discovery lifecycle (CandidateStatus) is preserved separately from validation truth.
              </span>
              <button
                onClick={() => setSelectedCandidate(null)}
                className="btn-secondary text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </AppLayout>
  );
}

