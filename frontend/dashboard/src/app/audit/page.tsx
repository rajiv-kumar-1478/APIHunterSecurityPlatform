"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
import { apiRequest } from "@/lib/api-client";

interface AuditListResponse {
  items?: AuditEventDto[];
}

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
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; email?: string } | null>(null);
  const [events, setEvents] = useState<AuditEventDto[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiRequest<{ isPlatformAdmin: boolean; email?: string }>("/api/v1/auth/me");
        if (!me.isPlatformAdmin) {
          router.replace("/dashboard");
          return;
        }
        setUser(me);
        await loadAuditLogs();
      } catch {
        router.replace("/login");
      }
    }
    void init();
  }, [router]);

  async function loadAuditLogs() {
    setLoading(true);
    try {
      const data = await apiRequest<AuditListResponse>("/api/v1/audit?page=1&pageSize=50");
      setEvents(data.items ?? []);
    } finally {
      setLoading(false);
    }
  }

  if (!user) return (
    <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
      <div className="flex flex-col items-center gap-3">
        <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
        <p className="text-xs text-[#7ba3c8] font-medium">Loading Audit Trail…</p>
      </div>
    </div>
  );

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="Immutable Security Audit Trail"
      subtitle="Comprehensive access audit trail with correlation IDs, IP tracking & payload context"
      actions={
        <button className="btn-secondary text-xs flex items-center gap-2" onClick={loadAuditLogs}>
          <span>↻ Refresh Logs</span>
        </button>
      }
    >
      <div className="glass-card overflow-hidden fade-in">
        <div className="overflow-x-auto">
          {loading ? (
            <div className="p-12 text-center text-[#7ba3c8] text-xs">
              <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              Loading audit events…
            </div>
          ) : events.length === 0 ? (
            <div className="p-12 text-center text-[#7ba3c8] text-xs">No audit events recorded yet.</div>
          ) : (
            <table className="w-full text-left border-collapse min-w-[750px]">
              <thead>
                <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Event Code</th>
                  <th className="p-4">User ID</th>
                  <th className="p-4">Correlation ID</th>
                  <th className="p-4">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
                {events.map((e) => (
                  <tr key={e.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4 text-xs text-[#7ba3c8]">{new Date(e.createdAtUtc).toLocaleString()}</td>
                    <td className="p-4">
                      <span className="badge badge-admin text-[10px]">
                        {e.eventCode}
                      </span>
                    </td>
                    <td className="p-4 font-mono text-xs text-[#e8f4ff]">{e.userId ?? "System"}</td>
                    <td className="p-4 font-mono text-xs text-[#00d4ff]">{e.correlationId}</td>
                    <td className="p-4 font-mono text-xs text-[#7ba3c8]">{e.ipAddress}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </AppLayout>
  );
}

