"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
import { apiRequest } from "@/lib/api-client";

interface ApiHunterRecordListResponse {
  items: ApiHunterRecord[];
  totalCount: number;
}

interface ApiHunterSyncResult {
  status: string;
  recordsImported: number;
  recordsUpdated: number;
}

interface ApiHunterSourceItem {
  Source: string;
  FoundUTC: string;
}

interface ApiHunterAwsMetadata {
  AwsAccountId?: string | null;
  AwsUserArn?: string | null;
  AwsUserId?: string | null;
  AwsCredentialType?: string | null;
  AwsAttachedPolicies?: string | null;
  AwsRiskLevel?: string | null;
  AwsIsRootAccount?: boolean;
}

interface ApiHunterKeyDetails {
  ApiKey: string;
  ApiTypeName: string;
  Status: number;
  StatusName: string;
  SearchProvider: string;
  Balance: string | null;
  AccountTier: string | null;
  FirstFoundUTC: string;
  LastFoundUTC: string;
  LastCheckedUTC: string | null;
  ErrorCount: number;
  FirstFoundIST: string;
  LastCheckedIST: string | null;
  TimesDisplayed: number;
  ValidationResponse: string | null;
  Metadata: string | null;
  DiscoveredByTelegramId: number | null;
  AwsMetadata: ApiHunterAwsMetadata | null;
  Sources: ApiHunterSourceItem[];
}

interface RevealedKeyResponse {
  recordId: string;
  rawKey: string;
  details?: ApiHunterKeyDetails;
}

interface SummaryData {
  source: {
    totalKeys: number;
    validKeys: number;
    validNoCreditsKeys: number;
    totalRepoReferences: number;
    isConnected: boolean;
  };
  imported: {
    total: number;
    valid: number;
    validNoCredits: number;
    repoReferences: number;
  };
  availableApiTypes?: string[];
  lastSync: {
    id: string;
    lastSyncedKeyId: number;
    status: string;
    recordsImported: number;
    recordsUpdated: number;
    lastSyncStartedAtUtc: string;
    lastSyncCompletedAtUtc: string | null;
    errorMessage: string | null;
  } | null;
}

interface ApiHunterRecord {
  id: string;
  sourceRecordId: number;
  maskedKey: string;
  status: string;
  apiType: string;
  searchProvider: string;
  firstFoundUtc: string;
  lastFoundUtc: string;
  lastCheckedUtc: string | null;
  balance: string | null;
  accountTier: string | null;
  awsAccountId: string | null;
  awsRiskLevel: string | null;
  repoCount: number;
}

export default function ApiHunterPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; userId: string; email?: string } | null>(null);
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [records, setRecords] = useState<ApiHunterRecord[]>([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [statusFilter, setStatusFilter] = useState("all");
  const [apiTypeFilter, setApiTypeFilter] = useState("all");
  const [providerFilter, setProviderFilter] = useState("all");
  const [hasReposFilter, setHasReposFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [availableApiTypes, setAvailableApiTypes] = useState<string[]>([]);
  const [availableProviders, setAvailableProviders] = useState<string[]>(["GitHub"]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [revealedData, setRevealedData] = useState<{ id: string; rawKey: string; details: ApiHunterKeyDetails } | null>(null);
  const [revealingId, setRevealingId] = useState<string | null>(null);
  const [activeModalTab, setActiveModalTab] = useState<"structured" | "json">("structured");
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  useEffect(() => {
    async function init() {
      try {
        const userData = await apiRequest<{
          isPlatformAdmin: boolean;
          userId: string;
          email?: string;
        }>("/api/v1/auth/me");
        setUser(userData);

        await fetchFilters();
        await fetchSummary();
        await fetchRecords(statusFilter, apiTypeFilter, providerFilter, hasReposFilter, searchQuery, page);
      } catch {
        router.replace("/login");
      } finally {
        setLoading(false);
      }
    }
    init();
  }, [router, page, statusFilter, apiTypeFilter, providerFilter, hasReposFilter]);

  async function fetchFilters() {
    try {
      const data = await apiRequest<{ apiTypes: string[]; providers: string[] }>("/api/v1/apihunter/filters");
      if (data.apiTypes && data.apiTypes.length > 0) {
        setAvailableApiTypes(data.apiTypes);
      }
      if (data.providers && data.providers.length > 0) {
        setAvailableProviders(data.providers);
      }
    } catch {
      // Fallback
    }
  }

  async function fetchSummary() {
    try {
      const data = await apiRequest<SummaryData>("/api/v1/apihunter/summary");
      setSummary(data);
      if (data.availableApiTypes && data.availableApiTypes.length > 0) {
        setAvailableApiTypes(data.availableApiTypes);
      }
    } catch (error: unknown) {
      console.error("Failed to fetch APIHunter summary", error);
    }
  }

  async function fetchRecords(
    status: string,
    apiType: string,
    provider: string,
    hasRepos: string,
    search: string,
    currentPage: number
  ) {
    try {
      const query = new URLSearchParams({
        status,
        page: String(currentPage),
        pageSize: "15",
      });

      if (apiType && apiType !== "all") {
        query.append("apiType", apiType);
      }
      if (provider && provider !== "all") {
        query.append("searchProvider", provider);
      }
      if (hasRepos === "yes") {
        query.append("hasRepos", "true");
      } else if (hasRepos === "no") {
        query.append("hasRepos", "false");
      }
      if (search && search.trim()) {
        query.append("search", search.trim());
      }

      const data = await apiRequest<ApiHunterRecordListResponse>(
        `/api/v1/apihunter/records?${query.toString()}`,
      );
      setRecords(data.items || []);
      setTotalRecords(data.totalCount || 0);
    } catch (error: unknown) {
      console.error("Failed to fetch records", error);
    }
  }

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    fetchRecords(statusFilter, apiTypeFilter, providerFilter, hasReposFilter, searchQuery, 1);
  }

  function handleResetFilters() {
    setStatusFilter("all");
    setApiTypeFilter("all");
    setProviderFilter("all");
    setHasReposFilter("all");
    setSearchQuery("");
    setPage(1);
    fetchRecords("all", "all", "all", "all", "", 1);
  }

  async function handleSync() {
    setSyncing(true);
    setSyncMessage(null);
    try {
      const result = await apiRequest<ApiHunterSyncResult>("/api/v1/apihunter/sync", {
        method: "POST",
      });
      setSyncMessage(
        `Sync ${result.status}! Imported: ${result.recordsImported}, Updated: ${result.recordsUpdated}`,
      );
      await fetchSummary();
      await fetchRecords(statusFilter, apiTypeFilter, providerFilter, hasReposFilter, searchQuery, page);
    } catch {
      setSyncMessage("Synchronization error occurred.");
    } finally {
      setSyncing(false);
    }
  }

  async function handleReveal(id: string) {
    setRevealingId(id);
    try {
      const data = await apiRequest<RevealedKeyResponse>(`/api/v1/apihunter/records/${id}/reveal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const details = data.details || {
        ApiKey: data.rawKey,
        ApiTypeName: "Unknown",
        Status: 1,
        StatusName: "Valid",
        SearchProvider: "GitHub",
        Balance: null,
        AccountTier: null,
        FirstFoundUTC: new Date().toISOString(),
        LastFoundUTC: new Date().toISOString(),
        LastCheckedUTC: null,
        ErrorCount: 0,
        FirstFoundIST: "",
        LastCheckedIST: null,
        TimesDisplayed: 0,
        ValidationResponse: null,
        Metadata: null,
        DiscoveredByTelegramId: null,
        AwsMetadata: null,
        Sources: [],
      };
      setRevealedData({ id, rawKey: data.rawKey || details.ApiKey, details });
      setActiveModalTab("structured");
      setCopiedKey(false);
      setCopiedJson(false);
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : "Error unmasking credential.";
      alert(`Failed to reveal key: ${msg}`);
    } finally {
      setRevealingId(null);
    }
  }

  if (loading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-[#7ba3c8] font-medium">Loading APIHunter Intelligence…</p>
        </div>
      </div>
    );
  }

  return (
    <AppLayout userEmail={user.email} isAdmin={user.isPlatformAdmin}>
      {/* Top Banner & Sync Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-[#00d4ff] animate-pulse" />
            <span className="text-xs font-semibold tracking-wider uppercase text-[#00d4ff]">
              External Source Intelligence
            </span>
          </div>
          <h1 className="text-2xl font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            APIHunter Ingestion Feed
          </h1>
          <p className="text-xs text-[#7ba3c8] mt-1">
            Continuous read-only ingestion pipeline from active leak detection agents and telegram crawlers.
          </p>
        </div>

        {user.isPlatformAdmin && (
          <div className="flex items-center gap-3">
            <button
              onClick={handleSync}
              disabled={syncing}
              className="btn-primary flex items-center gap-2 text-xs"
            >
              <svg
                className={`w-4 h-4 ${syncing ? "animate-spin" : ""}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              {syncing ? "Synchronizing…" : "Trigger Sync"}
            </button>
          </div>
        )}
      </div>

      {syncMessage && (
        <div className="p-3 mb-6 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/20 text-xs text-[#00d4ff] flex items-center justify-between">
          <span>{syncMessage}</span>
          <button onClick={() => setSyncMessage(null)} className="text-[#7ba3c8] hover:text-white">✕</button>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="glass-card p-5">
          <div className="flex items-center justify-between text-xs text-[#7ba3c8] mb-2 font-medium">
            <span>APIHUNTER SOURCE</span>
            <span
              className={`w-2 h-2 rounded-full ${
                summary?.source.isConnected ? "bg-[#00ff88]" : "bg-[#ff3366]"
              }`}
            />
          </div>
          <div className="text-xl font-bold text-[#e8f4ff] mb-1">
            {summary?.source.isConnected ? "Connected" : "Disconnected"}
          </div>
          <div className="text-xs text-[#7ba3c8]">
            Source Keys: {summary?.source.totalKeys.toLocaleString() ?? "0"}
          </div>
        </div>

        <div className="glass-card p-5">
          <div className="text-xs text-[#7ba3c8] mb-2 font-medium">IMPORTED KEYS</div>
          <div className="text-xl font-bold text-[#00d4ff] mb-1">
            {summary?.imported.total.toLocaleString() ?? "0"}
          </div>
          <div className="text-xs text-[#7ba3c8]">Platform Normalized Records</div>
        </div>

        <div className="glass-card p-5">
          <div className="text-xs text-[#7ba3c8] mb-2 font-medium">VALID KEYS</div>
          <div className="text-xl font-bold text-[#00ff88] mb-1">
            {summary?.imported.valid.toLocaleString() ?? "0"}
          </div>
          <div className="text-xs text-[#7ba3c8]">Active Working Credentials</div>
        </div>

        <div className="glass-card p-5">
          <div className="text-xs text-[#7ba3c8] mb-2 font-medium">VALID NO CREDITS</div>
          <div className="text-xl font-bold text-[#ffb800] mb-1">
            {summary?.imported.validNoCredits.toLocaleString() ?? "0"}
          </div>
          <div className="text-xs text-[#7ba3c8]">Valid Account (Zero Quota)</div>
        </div>
      </div>

      {/* Filter Tabs & Search Controls Bar */}
      <div className="glass-card overflow-hidden border-[#00d4ff]/10 mb-8">
        <div className="p-4 border-b border-[#00d4ff]/10 space-y-3">
          {/* Top Filter Controls: Status Tabs & Search Input */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              {["all", "Valid", "ValidNoCredits", "Unverified"].map((f) => (
                <button
                  key={f}
                  onClick={() => {
                    setStatusFilter(f);
                    setPage(1);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    statusFilter === f
                      ? "bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/30 shadow-sm"
                      : "text-[#7ba3c8] hover:text-white hover:bg-white/5"
                  }`}
                >
                  {f === "all" ? "All Records" : f}
                </button>
              ))}
            </div>

            {/* Quick Search Bar */}
            <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 max-w-md w-full">
              <div className="relative flex-1">
                <input
                  type="text"
                  placeholder="Search key, provider, balance, tier, or ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 bg-[#050811] border border-white/10 rounded-lg text-xs text-white placeholder-[#4a6580] focus:border-[#00d4ff]/50 focus:outline-none transition-all"
                />
                <svg className="w-4 h-4 text-[#7ba3c8] absolute left-2.5 top-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <button
                type="submit"
                className="px-3 py-1.5 bg-[#00d4ff]/20 hover:bg-[#00d4ff]/30 text-[#00d4ff] border border-[#00d4ff]/30 rounded-lg text-xs font-semibold transition-all"
              >
                Search
              </button>
            </form>
          </div>

          {/* Secondary Schema Filters Row: API Type dropdown, Provider dropdown, Repos Filter */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-white/5 text-xs">
            <div className="flex flex-wrap items-center gap-3">
              {/* API Type Dropdown */}
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-semibold text-[#7ba3c8] uppercase">API Type:</span>
                <select
                  value={apiTypeFilter}
                  onChange={(e) => {
                    setApiTypeFilter(e.target.value);
                    setPage(1);
                  }}
                  className="bg-[#050811] border border-white/10 rounded-lg px-2.5 py-1 text-xs text-[#e8f4ff] focus:border-[#00d4ff]/50 focus:outline-none transition-all"
                >
                  <option value="all">All Types ({availableApiTypes.length > 0 ? `${availableApiTypes.length} Available` : "All"})</option>
                  {availableApiTypes.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </div>

              {/* Search Provider Dropdown */}
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-semibold text-[#7ba3c8] uppercase">Provider:</span>
                <select
                  value={providerFilter}
                  onChange={(e) => {
                    setProviderFilter(e.target.value);
                    setPage(1);
                  }}
                  className="bg-[#050811] border border-white/10 rounded-lg px-2.5 py-1 text-xs text-[#e8f4ff] focus:border-[#00d4ff]/50 focus:outline-none transition-all"
                >
                  <option value="all">All Providers</option>
                  {availableProviders.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>

              {/* Has Linked Repositories Filter */}
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-semibold text-[#7ba3c8] uppercase">Linked Repos:</span>
                <select
                  value={hasReposFilter}
                  onChange={(e) => {
                    setHasReposFilter(e.target.value);
                    setPage(1);
                  }}
                  className="bg-[#050811] border border-white/10 rounded-lg px-2.5 py-1 text-xs text-[#e8f4ff] focus:border-[#00d4ff]/50 focus:outline-none transition-all"
                >
                  <option value="all">All (With & Without Repos)</option>
                  <option value="yes">Has Linked Repositories</option>
                  <option value="no">Zero Repo References</option>
                </select>
              </div>

              {/* Clear All Filters Button */}
              {(statusFilter !== "all" || apiTypeFilter !== "all" || providerFilter !== "all" || hasReposFilter !== "all" || searchQuery) && (
                <button
                  onClick={handleResetFilters}
                  className="text-xs text-[#ff4757] hover:underline font-medium"
                >
                  Clear Filters
                </button>
              )}
            </div>

            <div className="text-xs text-[#7ba3c8]">
              Found <span className="text-white font-semibold">{totalRecords.toLocaleString()}</span> matching records
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-white/5 text-[#7ba3c8] bg-white/[0.01]">
                <th className="p-4 font-semibold uppercase tracking-wider text-[10px]">Source ID</th>
                <th className="p-4 font-semibold uppercase tracking-wider text-[10px]">Masked Key</th>
                <th className="p-4 font-semibold uppercase tracking-wider text-[10px]">Status</th>
                <th className="p-4 font-semibold uppercase tracking-wider text-[10px]">Provider / Type</th>
                <th className="p-4 font-semibold uppercase tracking-wider text-[10px]">Repos</th>
                <th className="p-4 font-semibold uppercase tracking-wider text-[10px]">Discovered</th>
                {user.isPlatformAdmin && (
                  <th className="p-4 font-semibold uppercase tracking-wider text-[10px] text-right">Actions</th>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {records.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-[#7ba3c8]">
                    No records found in this category.
                  </td>
                </tr>
              ) : (
                records.map((r) => (
                  <tr key={r.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4 font-mono text-xs text-[#7ba3c8]">#{r.sourceRecordId}</td>
                    <td className="p-4 font-mono text-xs text-[#e8f4ff]">{r.maskedKey}</td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 text-[10px] font-semibold rounded-full border ${
                        r.status === "Valid" ? "badge-healthy" :
                        r.status === "ValidNoCredits" ? "badge-degraded" :
                        "badge-admin"
                      }`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="p-4 font-medium text-[#e8f4ff]">{r.apiType}</td>
                    <td className="p-4 text-xs text-[#7ba3c8]">{r.repoCount} references</td>
                    <td className="p-4 text-xs text-[#7ba3c8]">{new Date(r.firstFoundUtc).toLocaleDateString()}</td>
                    {user.isPlatformAdmin && (
                      <td className="p-4 text-right">
                        <button
                          disabled={revealingId === r.id}
                          onClick={() => handleReveal(r.id)}
                          className="px-3 py-1 text-xs rounded-lg border border-[#00d4ff]/30 text-[#00d4ff] hover:bg-[#00d4ff]/10 disabled:opacity-50 transition-all font-medium inline-flex items-center gap-1.5"
                        >
                          {revealingId === r.id ? (
                            <>
                              <span className="w-3 h-3 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
                              Revealing…
                            </>
                          ) : (
                            "Reveal"
                          )}
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        {totalRecords > 15 && (
          <div className="p-4 border-t border-[#00d4ff]/10 flex items-center justify-between text-xs text-[#7ba3c8]">
            <span>
              Page {page} of {Math.ceil(totalRecords / 15)}
            </span>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="px-3 py-1 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed font-medium text-white transition-all"
              >
                Previous
              </button>
              <button
                disabled={page >= Math.ceil(totalRecords / 15)}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed font-medium text-white transition-all"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Rich Revealed Key & Intelligence Modal */}
      {revealedData && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-md flex items-center justify-center p-4 z-50 fade-in">
          <div className="glass-card max-w-3xl w-full max-h-[92vh] flex flex-col border-[#00d4ff]/40 shadow-[0_0_50px_rgba(0,212,255,0.15)] overflow-hidden rounded-2xl">
            {/* Modal Header */}
            <div className="p-5 border-b border-[#00d4ff]/15 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-[#00d4ff]/10 border border-[#00d4ff]/30 flex items-center justify-center text-[#00d4ff]">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-base font-bold text-[#e8f4ff] flex items-center gap-2" style={{ fontFamily: "Outfit, sans-serif" }}>
                    APIHunter Intelligence Credential
                    <span className="px-2 py-0.5 text-[11px] rounded-full bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/30 font-mono">
                      {revealedData.details.ApiTypeName}
                    </span>
                  </h3>
                  <p className="text-xs text-[#7ba3c8]">
                    Audited reveal event recorded • Real unmasked credential & intelligence payload
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-1 text-xs font-semibold rounded-full border ${
                  revealedData.details.StatusName === "Valid" ? "badge-healthy" :
                  revealedData.details.StatusName === "ValidNoCredits" ? "badge-degraded" :
                  "badge-admin"
                }`}>
                  {revealedData.details.StatusName} (Code {revealedData.details.Status})
                </span>
                <button
                  onClick={() => setRevealedData(null)}
                  className="p-1.5 rounded-lg text-[#7ba3c8] hover:text-white hover:bg-white/10 transition-colors"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Unmasked Key Box */}
            <div className="p-5 pb-3 border-b border-[#00d4ff]/10 bg-[#060a12]">
              <div className="flex items-center justify-between text-[11px] font-semibold text-[#7ba3c8] uppercase tracking-wider mb-2">
                <span>Unmasked API Key</span>
                <span className="text-emerald-400 font-mono">Live Decrypted</span>
              </div>
              <div className="flex items-center gap-2 p-3 rounded-xl bg-[#03060c] border border-emerald-500/40 shadow-[inset_0_0_20px_rgba(16,185,129,0.05)]">
                <span className="font-mono text-sm text-emerald-400 break-all select-all flex-1 font-medium">
                  {revealedData.details.ApiKey || revealedData.rawKey}
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(revealedData.details.ApiKey || revealedData.rawKey);
                    setCopiedKey(true);
                    setTimeout(() => setCopiedKey(false), 2000);
                  }}
                  className="px-3 py-1.5 text-xs rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 transition-all font-medium shrink-0 flex items-center gap-1.5"
                >
                  {copiedKey ? (
                    <>
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      Copied!
                    </>
                  ) : (
                    <>
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                      Copy Key
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* View Tabs */}
            <div className="px-5 pt-3 border-b border-[#00d4ff]/10 flex items-center justify-between bg-white/[0.01]">
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveModalTab("structured")}
                  className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-all border-b-2 ${
                    activeModalTab === "structured"
                      ? "text-[#00d4ff] border-[#00d4ff] bg-[#00d4ff]/5"
                      : "text-[#7ba3c8] border-transparent hover:text-white"
                  }`}
                >
                  Structured Intelligence
                </button>
                <button
                  onClick={() => setActiveModalTab("json")}
                  className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-all border-b-2 flex items-center gap-1.5 ${
                    activeModalTab === "json"
                      ? "text-[#00d4ff] border-[#00d4ff] bg-[#00d4ff]/5"
                      : "text-[#7ba3c8] border-transparent hover:text-white"
                  }`}
                >
                  <span>Raw JSON View</span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-white/10 font-mono">schema</span>
                </button>
              </div>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(revealedData.details, null, 2));
                  setCopiedJson(true);
                  setTimeout(() => setCopiedJson(false), 2000);
                }}
                className="px-2.5 py-1 text-xs rounded-lg text-[#7ba3c8] hover:text-[#00d4ff] hover:bg-white/5 transition-all flex items-center gap-1"
              >
                {copiedJson ? "✓ JSON Copied" : "Copy JSON"}
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto max-h-[55vh] space-y-4">
              {activeModalTab === "structured" ? (
                <>
                  {/* Overview Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] font-semibold text-[#7ba3c8] uppercase block mb-1">Search Provider</span>
                      <span className="text-xs font-medium text-white">{revealedData.details.SearchProvider || "GitHub"}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] font-semibold text-[#7ba3c8] uppercase block mb-1">Account Balance</span>
                      <span className="text-xs font-medium text-white break-words">{revealedData.details.Balance || "N/A"}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] font-semibold text-[#7ba3c8] uppercase block mb-1">Account Tier</span>
                      <span className="text-xs font-medium text-white">{revealedData.details.AccountTier || "Standard / None"}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5">
                      <span className="text-[10px] font-semibold text-[#7ba3c8] uppercase block mb-1">Telegram Discovery</span>
                      <span className="text-xs font-mono text-white">
                        {revealedData.details.DiscoveredByTelegramId ? `#${revealedData.details.DiscoveredByTelegramId}` : "Scanner Feed"}
                      </span>
                    </div>
                  </div>

                  {/* Timestamps */}
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                    <h4 className="text-xs font-semibold text-[#e8f4ff] uppercase tracking-wider mb-2">Detection & Validation Timestamps</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-[#7ba3c8] block text-[11px]">First Found (UTC / IST):</span>
                        <span className="font-mono text-white text-[11px] block">{revealedData.details.FirstFoundUTC}</span>
                        {revealedData.details.FirstFoundIST && (
                          <span className="font-mono text-[#00d4ff] text-[11px] block">IST: {revealedData.details.FirstFoundIST}</span>
                        )}
                      </div>
                      <div>
                        <span className="text-[#7ba3c8] block text-[11px]">Last Checked (UTC / IST):</span>
                        <span className="font-mono text-white text-[11px] block">{revealedData.details.LastCheckedUTC || "Not yet re-checked"}</span>
                        {revealedData.details.LastCheckedIST && (
                          <span className="font-mono text-[#00d4ff] text-[11px] block">IST: {revealedData.details.LastCheckedIST}</span>
                        )}
                      </div>
                      <div>
                        <span className="text-[#7ba3c8] block text-[11px]">Last Found (UTC):</span>
                        <span className="font-mono text-white text-[11px]">{revealedData.details.LastFoundUTC}</span>
                      </div>
                      <div>
                        <span className="text-[#7ba3c8] block text-[11px]">Usage Stats:</span>
                        <span className="text-white text-[11px]">Displayed: {revealedData.details.TimesDisplayed} • Error Count: {revealedData.details.ErrorCount}</span>
                      </div>
                    </div>
                  </div>

                  {/* Sources / Repositories */}
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                    <h4 className="text-xs font-semibold text-[#e8f4ff] uppercase tracking-wider flex items-center justify-between">
                      <span>Source Repository References</span>
                      <span className="text-[11px] text-[#7ba3c8] font-normal">{revealedData.details.Sources?.length || 0} links</span>
                    </h4>
                    {revealedData.details.Sources && revealedData.details.Sources.length > 0 ? (
                      <div className="space-y-2">
                        {revealedData.details.Sources.map((s, idx) => (
                          <div key={idx} className="p-2.5 rounded-lg bg-[#080c14] border border-white/5 flex items-center justify-between gap-3 text-xs">
                            <a
                              href={s.Source}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[#00d4ff] hover:underline font-mono truncate flex-1 flex items-center gap-1.5"
                            >
                              <svg className="w-3.5 h-3.5 shrink-0" fill="currentColor" viewBox="0 0 24 24">
                                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                              </svg>
                              <span className="truncate">{s.Source}</span>
                            </a>
                            <span className="text-[10px] text-[#7ba3c8] font-mono shrink-0">
                              {new Date(s.FoundUTC).toLocaleDateString()}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-[#7ba3c8]">No direct repository URLs associated with this record.</p>
                    )}
                  </div>

                  {/* AWS Metadata (if present) */}
                  {revealedData.details.AwsMetadata && (
                    <div className="p-4 rounded-xl bg-amber-500/[0.03] border border-amber-500/20 space-y-2">
                      <h4 className="text-xs font-semibold text-amber-300 uppercase tracking-wider">AWS IAM Identity & Privileges</h4>
                      <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                        <div><span className="text-[#7ba3c8]">Account ID:</span> <span className="text-white">{revealedData.details.AwsMetadata.AwsAccountId || "N/A"}</span></div>
                        <div><span className="text-[#7ba3c8]">Risk Level:</span> <span className="text-amber-400 font-semibold">{revealedData.details.AwsMetadata.AwsRiskLevel || "N/A"}</span></div>
                        <div className="col-span-2"><span className="text-[#7ba3c8]">User ARN:</span> <span className="text-white break-all">{revealedData.details.AwsMetadata.AwsUserArn || "N/A"}</span></div>
                      </div>
                    </div>
                  )}

                  {/* Validation Response */}
                  {revealedData.details.ValidationResponse && (
                    <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                      <h4 className="text-xs font-semibold text-[#e8f4ff] uppercase tracking-wider">Validation Provider Response</h4>
                      <pre className="p-3 rounded-lg bg-[#080c14] border border-white/5 text-[11px] font-mono text-[#7ba3c8] overflow-x-auto whitespace-pre-wrap max-h-48">
                        {revealedData.details.ValidationResponse}
                      </pre>
                    </div>
                  )}

                  {/* Metadata */}
                  {revealedData.details.Metadata && (
                    <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 space-y-2">
                      <h4 className="text-xs font-semibold text-[#e8f4ff] uppercase tracking-wider">Key Metadata Payload</h4>
                      <pre className="p-3 rounded-lg bg-[#080c14] border border-white/5 text-[11px] font-mono text-[#7ba3c8] overflow-x-auto whitespace-pre-wrap max-h-48">
                        {revealedData.details.Metadata}
                      </pre>
                    </div>
                  )}
                </>
              ) : (
                /* Raw JSON View matching the exact user requested payload */
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-[#7ba3c8]">
                    <span>Complete APIHunter Intelligence Payload:</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(revealedData.details, null, 2));
                        setCopiedJson(true);
                        setTimeout(() => setCopiedJson(false), 2000);
                      }}
                      className="text-[#00d4ff] hover:underline flex items-center gap-1"
                    >
                      {copiedJson ? "✓ Copied to clipboard" : "Copy Raw JSON"}
                    </button>
                  </div>
                  <pre className="p-4 rounded-xl bg-[#03060c] border border-[#00d4ff]/25 text-[#00ff88] font-mono text-xs overflow-x-auto max-h-[48vh] leading-relaxed">
                    {JSON.stringify(revealedData.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[#00d4ff]/15 flex items-center justify-between bg-white/[0.02]">
              <div className="text-[11px] text-[#7ba3c8] flex items-center gap-1.5 font-mono">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                Immutable security audit entry logged
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(revealedData.details, null, 2));
                    setCopiedJson(true);
                    setTimeout(() => setCopiedJson(false), 2000);
                  }}
                  className="btn-secondary text-xs"
                >
                  {copiedJson ? "Copied JSON" : "Copy JSON"}
                </button>
                <button
                  onClick={() => setRevealedData(null)}
                  className="btn-primary text-xs"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </AppLayout>
  );
}
