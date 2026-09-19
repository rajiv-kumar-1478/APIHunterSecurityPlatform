"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

import { ApiError, apiRequest } from "@/lib/api-client";

interface NotificationTestResponse {
  message?: string;
}

interface ProviderStatus {
  name: string;
  channel: string;
  isHealthy: boolean;
  status: string;
  detail?: string;
  latencyMs?: number;
}

export default function NotificationsPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean } | null>(null);
  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [testEmail, setTestEmail] = useState("");
  const [sending, setSending] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiRequest<{ isPlatformAdmin: boolean }>("/api/v1/auth/me");
        if (!me.isPlatformAdmin) {
          router.replace("/dashboard");
          return;
        }
        setUser(me);
        await loadProviders();
      } catch {
        router.replace("/login");
      }
    }
    void init();
  }, [router]);

  async function loadProviders() {
    const data = await apiRequest<ProviderStatus[]>("/api/v1/notifications/providers");
    setProviders(data);
  }

  async function sendTest() {
    if (!testEmail) return;
    setSending(true);
    setTestResult(null);
    try {
      const data = await apiRequest<NotificationTestResponse>("/api/v1/notifications/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recipientEmail: testEmail }),
      });
      setTestResult({ ok: true, message: data.message ?? "Test notification sent." });
    } catch (error: unknown) {
      setTestResult({
        ok: false,
        message: error instanceof ApiError ? error.message : "Network error",
      });
    } finally {
      setSending(false);
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
        <div className="mb-8 fade-in">
          <h1 className="text-2xl font-bold" style={{ fontFamily: "Outfit, sans-serif" }}>
            Notification Providers
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
            Configure email notification adapters. Provider selected via EMAIL_PROVIDER environment variable.
          </p>
        </div>

        {/* Provider health status */}
        <div className="glass-card p-6 mb-6 fade-in">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold" style={{ fontFamily: "Outfit, sans-serif" }}>
              Email Providers
            </h2>
            <button className="btn-ghost text-sm" onClick={loadProviders}>↻ Refresh</button>
          </div>
          <div className="space-y-3">
            {providers.map((p, i) => (
              <div key={i} className="flex items-center justify-between p-4 rounded-xl"
                style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full"
                    style={{ background: p.isHealthy ? "var(--accent-green)" : "var(--accent-red)" }} />
                  <div>
                    <p className="font-medium text-sm" style={{ color: "var(--text-primary)" }}>{p.name}</p>
                    {p.detail && <p className="text-xs" style={{ color: "var(--text-muted)" }}>{p.detail}</p>}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {p.latencyMs !== undefined && (
                    <p className="text-xs mono" style={{ color: "var(--text-muted)" }}>{p.latencyMs.toFixed(1)}ms</p>
                  )}
                  <span className={`badge ${p.isHealthy ? "badge-healthy" : "badge-unhealthy"}`}>
                    {p.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Test notification */}
        <div className="glass-card p-6 fade-in">
          <h2 className="text-base font-semibold mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>
            Send Test Notification
          </h2>
          {testResult && (
            <div className="mb-4 p-3 rounded-lg text-sm"
              style={{
                background: testResult.ok ? "var(--accent-green-dim)" : "var(--accent-red-dim)",
                border: `1px solid ${testResult.ok ? "rgba(0,255,136,0.2)" : "rgba(255,71,87,0.25)"}`,
                color: testResult.ok ? "var(--accent-green)" : "var(--accent-red)"
              }}>
              {testResult.message}
            </div>
          )}
          <div className="flex gap-3">
            <input
              type="email"
              className="input-field flex-1"
              placeholder="recipient@email.com"
              value={testEmail}
              onChange={(e) => setTestEmail(e.target.value)}
            />
            <button className="btn-primary" onClick={sendTest} disabled={sending || !testEmail}>
              {sending ? "Sending…" : "Send Test"}
            </button>
          </div>
          <p className="mt-3 text-xs" style={{ color: "var(--text-muted)" }}>
            Sends a test email via the active provider (EMAIL_PROVIDER env var).
          </p>
        </div>
      </main>
    </div>
  );
}
