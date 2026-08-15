"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

interface AuditEventDto {
  id: string;
  eventCode: string;
  userId?: string;
  correlationId: string;
  ipAddress: string;
  payload?: string;
  createdAtUtc: string;
}

export default function AuditPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean } | null>(null);
  const [events, setEvents] = useState<AuditEventDto[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function init() {
      const meRes = await fetch(`${API_URL}/api/v1/auth/me`, { credentials: "include" });
      if (!meRes.ok) { router.replace("/login"); return; }
      const me = await meRes.json();
      if (!me.isPlatformAdmin) { router.replace("/dashboard"); return; }
      setUser(me);
      await loadAuditLogs();
    }
    init();
  }, [router]);

  async function loadAuditLogs() {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/audit?page=1&pageSize=50`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setEvents(data.items ?? []);
      }
    } finally {
      setLoading(false);
    }
  }

  if (!user) return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-8 h-8 border-2 border-current border-t-transparent rounded-full animate-spin"
        style={{ color: "var(--accent-cyan)" }} />
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar isAdmin={user.isPlatformAdmin} />
      <main className="flex-1 overflow-auto p-8">
        <div className="flex items-center justify-between mb-8 fade-in">
          <div>
            <h1 className="text-2xl font-bold" style={{ fontFamily: "Outfit, sans-serif" }}>
              Audit Log
            </h1>
            <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
              Immutable audit trail with correlation IDs & payload context
            </p>
          </div>
          <button className="btn-ghost" onClick={loadAuditLogs}>↻ Refresh</button>
        </div>

        <div className="glass-card overflow-hidden fade-in">
          {loading ? (
            <div className="p-8 text-center" style={{ color: "var(--text-muted)" }}>Loading audit events…</div>
          ) : events.length === 0 ? (
            <div className="p-8 text-center" style={{ color: "var(--text-muted)" }}>No audit events recorded yet.</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Code</th>
                  <th>User ID</th>
                  <th>Correlation ID</th>
                  <th>IP Address</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td className="text-xs">{new Date(e.createdAtUtc).toLocaleString()}</td>
                    <td>
                      <span className="badge" style={{ background: "rgba(0,212,255,0.1)", color: "var(--accent-cyan)" }}>
                        {e.eventCode}
                      </span>
                    </td>
                    <td className="mono text-xs">{e.userId ?? "System"}</td>
                    <td className="mono text-xs" style={{ color: "var(--text-muted)" }}>{e.correlationId}</td>
                    <td className="mono text-xs">{e.ipAddress}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </main>
    </div>
  );
}
