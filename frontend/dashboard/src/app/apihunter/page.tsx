"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

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
  const [totalRecords, setTotalRecords] = useState(0);
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState<{ id: string; key: string } | null>(null);

  useEffect(() => {
    async function init() {
      try {
        const res = await fetch(`${API_URL}/api/v1/auth/me`, { credentials: "include" });
        if (!res.ok) { router.replace("/login"); return; }
        const uData = await res.json();
        setUser(uData);

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
      const res = await fetch(`${API_URL}/api/v1/apihunter/summary`, { credentials: "include" });
      if (res.ok) setSummary(await res.json());
    } catch (e) {
      console.error("Failed to fetch APIHunter summary", e);
    }
  }

  async function fetchRecords(filter: string, p: number) {
    try {
      const res = await fetch(`${API_URL}/api/v1/apihunter/records?status=${filter}&page=${p}&pageSize=15`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setRecords(data.items);
        setTotalRecords(data.totalCount);
      }
    } catch (e) {
      console.error("Failed to fetch records", e);
    }
  }

  async function handleSync() {
    setSyncing(true);
    setSyncMessage(null);
    try {
      const csrf = sessionStorage.getItem("csrf_token") ?? "";
      const res = await fetch(`${API_URL}/api/v1/apihunter/sync`, {
        method: "POST",
        credentials: "include",
        headers: { "X-CSRF-TOKEN": csrf }
      });
      if (res.ok) {
        const result = await res.json();
        setSyncMessage(`Sync ${result.status}! Imported: ${result.recordsImported}, Updated: ${result.recordsUpdated}`);
        await fetchSummary();
        await fetchRecords(statusFilter, page);
      } else {
        setSyncMessage("Failed to trigger synchronization.");
      }
    } catch {
      setSyncMessage("Synchronization error occurred.");
    } finally {
      setSyncing(false);
    }
  }

  async function handleReveal(id: string) {
    try {
      const csrf = sessionStorage.getItem("csrf_token") ?? "";
      const res = await fetch(`${API_URL}/api/v1/apihunter/records/${id}/reveal`, {
        method: "POST",
        credentials: "include",
        headers: { "X-CSRF-TOKEN": csrf }
      });
      if (res.ok) {
        const data = await res.json();
        setRevealedKey({ id, key: data.rawKey });
      }
    } catch {
      alert("Failed to reveal key");
    }
  }

  if (loading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-current border-t-transparent rounded-full animate-spin"
          style={{ color: "var(--accent-cyan)" }} />
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar isAdmin={user.isPlatformAdmin} userEmail={user.email} />

      <main className="flex-1 overflow-y-auto p-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold tracking-tight" style={{ fontFamily: "Outfit, sans-serif" }}>
              APIHunter Security Intelligence
            </h1>
            <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
              Read-only synchronization adapter & credential analysis center
            </p>
          </div>
          {user.isPlatformAdmin && (
            <button
              onClick={handleSync}
              disabled={syncing}
              className="btn btn-primary flex items-center gap-2"
            >
              {syncing ? (
                <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
                </svg>
              )}
              {syncing ? "Synchronizing…" : "Sync From APIHunter"}
            </button>
          )}
        </div>

        {syncMessage && (
          <div className="mb-6 p-4 rounded-xl border flex items-center justify-between"
            style={{ background: "rgba(0,212,255,0.05)", borderColor: "rgba(0,212,255,0.2)", color: "var(--accent-cyan)" }}>
            <span>{syncMessage}</span>
            <button onClick={() => setSyncMessage(null)} className="text-xs hover:underline">Dismiss</button>
          </div>
        )}

        {/* Summary Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-5 mb-8">
          <div className="glass-card p-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
                APIHunter Source
              </span>
              <span className={`w-2.5 h-2.5 rounded-full ${summary?.source.isConnected ? "bg-emerald-400" : "bg-red-400"}`} />
            </div>
            <div className="text-2xl font-bold" style={{ color: "var(--text-primary)" }}>
              {summary?.source.isConnected ? "Connected" : "Disconnected"}
            </div>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              Source Keys: {summary?.source.totalKeys.toLocaleString() ?? 0}
            </p>
          </div>

          <div className="glass-card p-5">
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Imported Keys
            </span>
            <div className="text-2xl font-bold mt-2" style={{ color: "var(--accent-cyan)" }}>
              {summary?.imported.total.toLocaleString() ?? 0}
            </div>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              Platform Normalized Records
            </p>
          </div>

          <div className="glass-card p-5">
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Valid Keys
            </span>
            <div className="text-2xl font-bold mt-2" style={{ color: "var(--accent-green)" }}>
              {summary?.imported.valid.toLocaleString() ?? 0}
            </div>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              Active Working Credentials
            </p>
          </div>

          <div className="glass-card p-5">
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Valid No Credits
            </span>
            <div className="text-2xl font-bold mt-2" style={{ color: "var(--accent-amber)" }}>
              {summary?.imported.validNoCredits.toLocaleString() ?? 0}
            </div>
            <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
              Valid Account (Zero Quota)
            </p>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex items-center gap-2 mb-6 border-b pb-3" style={{ borderColor: "var(--border-subtle)" }}>
          {["all", "Valid", "ValidNoCredits", "Invalid", "Unverified"].map((f) => (
            <button
              key={f}
              onClick={() => { setStatusFilter(f); setPage(1); }}
              className={`px-4 py-2 text-xs font-medium rounded-lg transition-all ${
                statusFilter === f
                  ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                  : "text-slate-400 hover:bg-slate-800/50"
              }`}
            >
              {f === "all" ? "All Records" : f}
            </button>
          ))}
        </div>

        {/* Records Table */}
        <div className="glass-card overflow-hidden">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b text-xs font-semibold uppercase" style={{ borderColor: "var(--border-subtle)", color: "var(--text-muted)" }}>
                <th className="p-4">Source ID</th>
                <th className="p-4">Masked Key</th>
                <th className="p-4">Status</th>
                <th className="p-4">Provider / Type</th>
                <th className="p-4">Repos</th>
                <th className="p-4">Discovered</th>
                {user.isPlatformAdmin && <th className="p-4 text-right">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y text-sm" style={{ borderColor: "var(--border-subtle)" }}>
              {records.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center" style={{ color: "var(--text-muted)" }}>
                    No imported APIHunter records found. Click &quot;Sync From APIHunter&quot; to import intelligence data.
                  </td>
                </tr>
              ) : (
                records.map((r) => (
                  <tr key={r.id} className="hover:bg-white/[0.02]">
                    <td className="p-4 font-mono text-xs text-slate-400">#{r.sourceRecordId}</td>
                    <td className="p-4 font-mono text-xs" style={{ color: "var(--text-primary)" }}>{r.maskedKey}</td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 text-xs font-semibold rounded-full border ${
                        r.status === "Valid" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
                        r.status === "ValidNoCredits" ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                        r.status === "Invalid" ? "bg-rose-500/10 text-rose-400 border-rose-500/20" :
                        "bg-slate-500/10 text-slate-400 border-slate-500/20"
                      }`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="p-4 font-medium" style={{ color: "var(--text-primary)" }}>{r.apiType}</td>
                    <td className="p-4 text-xs text-slate-400">{r.repoCount} references</td>
                    <td className="p-4 text-xs text-slate-400">{new Date(r.firstFoundUtc).toLocaleDateString()}</td>
                    {user.isPlatformAdmin && (
                      <td className="p-4 text-right">
                        <button
                          onClick={() => handleReveal(r.id)}
                          className="px-3 py-1 text-xs rounded-lg border hover:bg-white/5 transition-all"
                          style={{ borderColor: "var(--border-subtle)", color: "var(--accent-cyan)" }}
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

        {/* Revealed Key Modal */}
        {revealedKey && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <div className="glass-card p-6 max-w-lg w-full">
              <h3 className="text-lg font-bold mb-3" style={{ color: "var(--text-primary)" }}>
                Credential Unmasked (Audited)
              </h3>
              <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
                This reveal event has been recorded in the platform audit log.
              </p>
              <div className="p-3 rounded-lg font-mono text-xs break-all mb-6"
                style={{ background: "rgba(0,0,0,0.5)", border: "1px solid var(--border-subtle)", color: "var(--accent-green)" }}>
                {revealedKey.key}
              </div>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => { navigator.clipboard.writeText(revealedKey.key); }}
                  className="btn btn-secondary text-xs"
                >
                  Copy to Clipboard
                </button>
                <button
                  onClick={() => setRevealedKey(null)}
                  className="btn btn-primary text-xs"
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
