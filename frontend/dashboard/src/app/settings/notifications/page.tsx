"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
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
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; email?: string } | null>(null);
  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [testEmail, setTestEmail] = useState("");
  const [sending, setSending] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiRequest<{ isPlatformAdmin: boolean; email?: string }>("/api/v1/auth/me");
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
    try {
      const data = await apiRequest<ProviderStatus[]>("/api/v1/notifications/providers");
      setProviders(data);
    } catch (err: unknown) {
      console.error("Failed to fetch notification providers:", err);
    }
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
      setTestResult({ ok: true, message: data.message ?? "Test notification sent successfully." });
    } catch (error: unknown) {
      setTestResult({
        ok: false,
        message: error instanceof ApiError ? error.message : "Network error delivering notification.",
      });
    } finally {
      setSending(false);
    }
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="Notification Providers"
      subtitle="Configure email notification adapters. Active provider selected via EMAIL_PROVIDER environment variable."
      actions={
        <button className="btn-secondary text-xs flex items-center gap-1.5" onClick={loadProviders}>
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" /></svg>
          <span>Refresh Providers</span>
        </button>
      }
    >
      {/* Provider Health Status Section */}
      <div className="glass-card p-6 fade-in space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
            Configured Email Adapters
          </h2>
          <span className="text-xs text-[#7ba3c8] font-medium">{providers.length} Registered</span>
        </div>

        <div className="space-y-3">
          {providers.length === 0 ? (
            <p className="text-xs text-[#7ba3c8] py-4 text-center">No notification providers registered.</p>
          ) : (
            providers.map((p, i) => (
              <div
                key={i}
                className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-xl gap-3"
                style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-2.5 h-2.5 rounded-full ${p.isHealthy ? "bg-[#00ff88]" : "bg-[#ff4757] animate-pulse"}`}
                  />
                  <div>
                    <p className="font-bold text-sm text-[#e8f4ff]">{p.name}</p>
                    {p.detail && <p className="text-xs text-[#7ba3c8] mt-0.5">{p.detail}</p>}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {p.latencyMs !== undefined && (
                    <p className="text-xs font-mono text-[#7ba3c8]">{p.latencyMs.toFixed(1)}ms</p>
                  )}
                  <span className={`badge ${p.isHealthy ? "badge-healthy" : "badge-unhealthy"}`}>
                    {p.status}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Send Test Notification Section */}
      <div className="glass-card p-6 fade-in space-y-4">
        <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
          Send Diagnostic Test Notification
        </h2>

        {testResult && (
          <div
            className={`p-4 rounded-xl border text-xs font-semibold flex items-center justify-between ${
              testResult.ok
                ? "bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]"
                : "bg-[#ff4757]/10 border-[#ff4757]/30 text-[#ff4757]"
            }`}
          >
            <span>{testResult.message}</span>
            <button onClick={() => setTestResult(null)} className="hover:underline font-bold">✕</button>
          </div>
        )}

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="email"
            className="w-full sm:flex-1 bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-3 text-xs text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
            placeholder="recipient@example.com"
            value={testEmail}
            onChange={(e) => setTestEmail(e.target.value)}
          />
          <button
            className="btn-primary text-xs py-3 px-6 whitespace-nowrap"
            onClick={sendTest}
            disabled={sending || !testEmail}
          >
            {sending ? "Delivering…" : "Send Test Email"}
          </button>
        </div>

        <p className="text-xs text-[#7ba3c8]">
          Dispatches a live test security alert through the active email provider adapter.
        </p>
      </div>
    </AppLayout>
  );
}

