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

interface RevealedKeyResponse {
  rawKey: string;
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
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState<{ id: string; key: string } | null>(null);

  useEffect(() => {
    async function init() {
      try {
        const userData = await apiRequest<{
          isPlatformAdmin: boolean;
          userId: string;
          email?: string;
        }>("/api/v1/auth/me");
        setUser(userData);

        await fetchSummary();
        await fetchRecords(statusFilter, page);
      } catch {
        router.replace("/login");
      } finally {
        setLoading(false);
      }
    }
    init();
  }, [router, page, statusFilter]);

  async function fetchSummary() {
    try {
      const data = await apiRequest<SummaryData>("/api/v1/apihunter/summary");
      setSummary(data);
    } catch (error: unknown) {
      console.error("Failed to fetch APIHunter summary", error);
    }
  }

  async function fetchRecords(filter: string, currentPage: number) {
    try {
      const query = new URLSearchParams({
        status: filter,
        page: String(currentPage),
        pageSize: "15",
      });
      const data = await apiRequest<ApiHunterRecordListResponse>(
        `/api/v1/apihunter/records?${query.toString()}`,
      );
      setRecords(data.items);
    } catch (error: unknown) {
      console.error("Failed to fetch records", error);
    }
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
      await fetchRecords(statusFilter, page);
    } catch {
      setSyncMessage("Synchronization error occurred.");
    } finally {
      setSyncing(false);
    }
  }

  async function handleReveal(id: string) {
    try {
      const data = await apiRequest<RevealedKeyResponse>(`/api/v1/apihunter/records/${id}/reveal`, {
        method: "POST",
      });
      setRevealedKey({ id, key: data.rawKey });
    } catch {
      alert("Failed to reveal key");
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
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="APIHunter Security Intelligence"
      subtitle="Read-only synchronization adapter & credential analysis center"
      actions={
        user.isPlatformAdmin ? (
          <button
            onClick={handleSync}
            disabled={syncing}
            className="btn-primary text-xs flex items-center gap-2"
          >
            {syncing ? (
              <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
              </svg>
            )}
            {syncing ? "Synchronizing…" : "Sync From APIHunter"}
          </button>
        ) : undefined
      }
    >
      {syncMessage && (
        <div className="p-4 rounded-xl border border-[#00d4ff]/30 bg-[#00d4ff]/10 text-[#00d4ff] text-xs flex items-center justify-between fade-in">
          <span>{syncMessage}</span>
          <button onClick={() => setSyncMessage(null)} className="text-xs hover:underline font-semibold">
            Dismiss
          </button>
        </div>
      )}

      {/* Summary Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 fade-in">
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-[#4a6580]">
              APIHunter Source
            </span>
            <span className={`w-2.5 h-2.5 rounded-full ${summary?.source.isConnected ? "bg-[#00ff88]" : "bg-[#ff4757]"}`} />
          </div>
          <div className="text-2xl font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            {summary?.source.isConnected ? "Connected" : "Disconnected"}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">
            Source Keys: {summary?.source.totalKeys.toLocaleString() ?? 0}
          </p>
        </div>

        <div className="glass-card p-5">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#4a6580]">
            Imported Keys
          </span>
          <div className="text-2xl font-bold text-[#00d4ff] mt-2" style={{ fontFamily: "Outfit, sans-serif" }}>
            {summary?.imported.total.toLocaleString() ?? 0}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">
            Platform Normalized Records
          </p>
        </div>

        <div className="glass-card p-5">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#4a6580]">
            Valid Keys
          </span>
          <div className="text-2xl font-bold text-[#00ff88] mt-2" style={{ fontFamily: "Outfit, sans-serif" }}>
            {summary?.imported.valid.toLocaleString() ?? 0}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">
            Active Working Credentials
          </p>
        </div>

        <div className="glass-card p-5">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#4a6580]">
            Valid No Credits
          </span>
          <div className="text-2xl font-bold text-[#ffa502] mt-2" style={{ fontFamily: "Outfit, sans-serif" }}>
            {summary?.imported.validNoCredits.toLocaleString() ?? 0}
          </div>
          <p className="text-xs text-[#7ba3c8] mt-1">
            Valid Account (Zero Quota)
          </p>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2 fade-in">
        {["all", "Valid", "ValidNoCredits", "Invalid", "Unverified"].map((f) => (
          <button
            key={f}
            onClick={() => { setStatusFilter(f); setPage(1); }}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
              statusFilter === f
                ? "bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/40 shadow-sm"
                : "bg-white/5 text-[#7ba3c8] border border-white/10 hover:text-white"
            }`}
          >
            {f === "all" ? "All Records" : f}
          </button>
        ))}
      </div>

      {/* Records Table Container */}
      <div className="glass-card overflow-hidden fade-in">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[700px]">
            <thead>
              <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                <th className="p-4">Source ID</th>
                <th className="p-4">Masked Key</th>
                <th className="p-4">Status</th>
                <th className="p-4">Provider / Type</th>
                <th className="p-4">Repos</th>
                <th className="p-4">Discovered</th>
                {user.isPlatformAdmin && <th className="p-4 text-right">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
              {records.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-[#7ba3c8]">
                    No imported APIHunter records found. Click &quot;Sync From APIHunter&quot; to import intelligence data.
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
                        r.status === "Invalid" ? "badge-unhealthy" :
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
                          onClick={() => handleReveal(r.id)}
                          className="px-3 py-1 text-xs rounded-lg border border-[#00d4ff]/30 text-[#00d4ff] hover:bg-[#00d4ff]/10 transition-all font-medium"
                        >
                          Reveal
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Revealed Key Modal */}
      {revealedKey && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50 fade-in">
          <div className="glass-card p-6 max-w-lg w-full border-[#00d4ff]/30">
            <h3 className="text-lg font-bold text-[#e8f4ff] mb-2" style={{ fontFamily: "Outfit, sans-serif" }}>
              Credential Unmasked (Audited)
            </h3>
            <p className="text-xs text-[#7ba3c8] mb-4">
              This reveal event has been logged to the immutable security audit trail.
            </p>
            <div className="p-3.5 rounded-xl font-mono text-xs break-all mb-6 bg-[#080c14] border border-[#00ff88]/30 text-[#00ff88]">
              {revealedKey.key}
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => { navigator.clipboard.writeText(revealedKey.key); }}
                className="btn-secondary text-xs"
              >
                Copy to Clipboard
              </button>
              <button
                onClick={() => setRevealedKey(null)}
                className="btn-primary text-xs"
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

