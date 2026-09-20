"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
import { apiFetch, getErrorMessage } from "@/lib/api-client";

interface RegisteredApp {
  id: string;
  applicationId: string;
  displayName: string;
  authorizedTargetUrl: string;
  environment: string;
  enabled: boolean;
  createdAtUtc: string;
  updatedAtUtc: string;
}

interface RegistrationResult {
  application: RegisteredApp;
  rawSigningSecret: string;
}

interface SecretRotationResult {
  id: string;
  applicationId: string;
  rawSigningSecret: string;
}

export default function DeploymentsPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; userId: string; email?: string } | null>(null);
  const [applications, setApplications] = useState<RegisteredApp[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Registration Modal State
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [newAppId, setNewAppId] = useState("");
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newTargetUrl, setNewTargetUrl] = useState("");
  const [newEnvironment, setNewEnvironment] = useState("Production");
  const [submitting, setSubmitting] = useState(false);

  // Secret Modal State
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null);
  const [secretAppName, setSecretAppName] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const [showRawSecret, setShowRawSecret] = useState(false);

  const fetchApplications = useCallback(async () => {
    try {
      const res = await apiFetch("/api/v1/applications");
      if (res.ok) {
        const data = await res.json();
        setApplications(data);
        setError(null);
      } else {
        setError(`Failed to load applications (${res.status})`);
      }
    } catch (err) {
      setError(getErrorMessage(err, "Failed to load registered applications."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    async function init() {
      try {
        const res = await apiFetch("/api/v1/auth/me");
        if (res.ok) {
          const userData = await res.json();
          setUser(userData);
          await fetchApplications();
        } else {
          router.replace("/login");
        }
      } catch {
        router.replace("/login");
      }
    }
    void init();
  }, [router, fetchApplications]);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAppId || !newTargetUrl) return;

    setSubmitting(true);
    setError(null);
    try {
      const res = await apiFetch("/api/v1/applications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          applicationId: newAppId.trim(),
          displayName: newDisplayName.trim() || newAppId.trim(),
          authorizedTargetUrl: newTargetUrl.trim(),
          environment: newEnvironment,
        }),
      });

      if (res.ok) {
        const result: RegistrationResult = await res.json();
        setShowRegisterModal(false);
        setNewAppId("");
        setNewDisplayName("");
        setNewTargetUrl("");
        setNewEnvironment("Production");
        setSecretAppName(result.application.displayName);
        setGeneratedSecret(result.rawSigningSecret);
        setActionSuccess(`Application '${result.application.displayName}' registered successfully.`);
        fetchApplications();
      } else {
        const errData = await res.json().catch(() => ({}));
        setError(errData.message || `Registration failed (${res.status})`);
      }
    } catch (err) {
      setError(getErrorMessage(err, "Failed to register application."));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegenerateSecret = async (app: RegisteredApp) => {
    if (!confirm(`Are you sure you want to regenerate the HMAC secret for '${app.displayName}'? The previous key will stop working immediately.`)) {
      return;
    }

    try {
      const res = await apiFetch(`/api/v1/applications/${app.id}/regenerate-secret`, {
        method: "POST",
      });

      if (res.ok) {
        const result: SecretRotationResult = await res.json();
        setSecretAppName(app.displayName);
        setGeneratedSecret(result.rawSigningSecret);
        setActionSuccess(`Signing secret rotated for '${app.displayName}'.`);
      } else {
        setError(`Failed to rotate secret (${res.status})`);
      }
    } catch (err) {
      setError(getErrorMessage(err, "Failed to rotate signing secret."));
    }
  };

  const handleToggleStatus = async (app: RegisteredApp) => {
    try {
      const res = await apiFetch(`/api/v1/applications/${app.id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !app.enabled }),
      });

      if (res.ok) {
        setActionSuccess(`Application '${app.displayName}' is now ${!app.enabled ? "enabled" : "disabled"}.`);
        fetchApplications();
      } else {
        setError(`Failed to update status (${res.status})`);
      }
    } catch (err) {
      setError(getErrorMessage(err, "Failed to update application status."));
    }
  };

  const handleDelete = async (app: RegisteredApp) => {
    if (!confirm(`Delete application '${app.displayName}'? Any webhooks sent with this Application ID will be rejected.`)) {
      return;
    }

    try {
      const res = await apiFetch(`/api/v1/applications/${app.id}`, {
        method: "DELETE",
      });

      if (res.ok) {
        setActionSuccess(`Application '${app.displayName}' deleted.`);
        fetchApplications();
      } else {
        setError(`Failed to delete application (${res.status})`);
      }
    } catch (err) {
      setError(getErrorMessage(err, "Failed to delete application."));
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      alert("Please copy manually from the input.");
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-[#7ba3c8] font-medium">Loading Deployments Center…</p>
        </div>
      </div>
    );
  }

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="CI/CD Deployment Applications"
      subtitle="Manage registered applications, authorized target scan URLs & HMAC-SHA256 deployment gates"
      actions={
        <button
          id="btn-register-app"
          onClick={() => setShowRegisterModal(true)}
          className="btn-primary text-xs flex items-center gap-2"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Register Application
        </button>
      }
    >
      {/* Notifications */}
      {error && (
        <div className="p-4 rounded-xl border border-[#ff4757]/30 bg-[#ff4757]/10 text-[#ff4757] text-xs font-semibold fade-in">
          {error}
        </div>
      )}
      {actionSuccess && (
        <div className="p-4 rounded-xl border border-[#00ff88]/30 bg-[#00ff88]/10 text-[#00ff88] text-xs font-semibold fade-in">
          {actionSuccess}
        </div>
      )}

      {/* Application List Table Container */}
      <div className="glass-card overflow-hidden fade-in">
        <div className="overflow-x-auto">
          {loading ? (
            <div className="p-12 text-center text-[#7ba3c8] text-xs">
              <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              Loading deployment applications...
            </div>
          ) : applications.length === 0 ? (
            <div className="p-12 text-center text-[#7ba3c8] space-y-2">
              <p className="text-sm font-semibold text-[#e8f4ff]">No applications registered yet.</p>
              <p className="text-xs">
                Click &quot;Register Application&quot; to authorize a deployment target and generate an HMAC webhook secret.
              </p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse min-w-[800px]">
              <thead>
                <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                  <th className="p-4">Application</th>
                  <th className="p-4">App ID</th>
                  <th className="p-4">Environment</th>
                  <th className="p-4">Authorized Target URL</th>
                  <th className="p-4">Status</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
                {applications.map((app) => (
                  <tr key={app.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4 font-bold text-[#e8f4ff]">{app.displayName}</td>
                    <td className="p-4">
                      <code className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-[#00d4ff] font-mono text-[11px]">
                        {app.applicationId}
                      </code>
                    </td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 text-[10px] font-semibold rounded-full border ${
                        app.environment.toLowerCase() === "production"
                          ? "badge-unhealthy"
                          : "badge-degraded"
                      }`}>
                        {app.environment}
                      </span>
                    </td>
                    <td className="p-4 text-[#7ba3c8]">{app.authorizedTargetUrl}</td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 text-[10px] font-semibold rounded-full border ${
                        app.enabled ? "badge-healthy" : "badge-admin"
                      }`}>
                        {app.enabled ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td className="p-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleRegenerateSecret(app)}
                          className="btn-secondary text-[11px] py-1 px-2.5"
                        >
                          Rotate Secret
                        </button>
                        <button
                          onClick={() => handleToggleStatus(app)}
                          className="btn-secondary text-[11px] py-1 px-2.5"
                        >
                          {app.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          onClick={() => handleDelete(app)}
                          className="px-2.5 py-1 rounded-lg border border-[#ff4757]/30 text-[#ff4757] hover:bg-[#ff4757]/10 text-[11px] font-medium transition-all"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Integration Instructions Card */}
      <div className="glass-card p-6 fade-in space-y-3">
        <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
          How to Connect Your CI/CD Pipeline
        </h2>
        <p className="text-xs text-[#7ba3c8] leading-relaxed">
          When a deployment succeeds, send a webhook payload signed with your HMAC secret to enqueue an incremental verification scan.
        </p>
        <div className="p-4 rounded-xl bg-[#080c14] border border-[#00d4ff]/20 overflow-x-auto">
          <pre className="text-xs font-mono text-[#00d4ff] leading-relaxed">
{`# 1. Prepare JSON body
PAYLOAD='{"applicationId":"YOUR_APP_ID","commitSha":"\${GITHUB_SHA}","branch":"main"}'
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 2. Compute HMAC-SHA256 signature
SIGNATURE="sha256=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "YOUR_HMAC_SECRET" | sed 's/^.* //')"

# 3. Deliver to APIHunter deployment webhook endpoint
curl -X POST https://apihunter-api.onrender.com/api/v1/webhooks/deployments \\
  -H "Content-Type: application/json" \\
  -H "X-Webhook-Id: $(uuidgen)" \\
  -H "X-Webhook-Timestamp: $TIMESTAMP" \\
  -H "X-Hub-Signature-256: $SIGNATURE" \\
  -d "$PAYLOAD"`}
          </pre>
        </div>
      </div>

      {/* Register Application Modal */}
      {showRegisterModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50 fade-in">
          <div className="glass-card p-6 max-w-lg w-full border-[#00d4ff]/30">
            <h2 className="text-lg font-bold text-[#e8f4ff] mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>
              Register CI/CD Application
            </h2>
            <form onSubmit={handleRegister} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">
                  Application ID (Unique key used in webhooks) *
                </label>
                <input
                  id="input-app-id"
                  type="text"
                  required
                  placeholder="e.g. web-app-prod"
                  value={newAppId}
                  onChange={(e) => setNewAppId(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">
                  Display Name
                </label>
                <input
                  id="input-display-name"
                  type="text"
                  placeholder="e.g. Core Web Application (Production)"
                  value={newDisplayName}
                  onChange={(e) => setNewDisplayName(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">
                  Authorized Target URL (Server-controlled destination) *
                </label>
                <input
                  id="input-target-url"
                  type="url"
                  required
                  placeholder="https://api.mycompany.com"
                  value={newTargetUrl}
                  onChange={(e) => setNewTargetUrl(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">
                  Environment
                </label>
                <select
                  value={newEnvironment}
                  onChange={(e) => setNewEnvironment(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
                >
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="QA">QA</option>
                  <option value="Development">Development</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  className="btn-secondary text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="btn-primary text-xs"
                >
                  {submitting ? "Registering..." : "Register & Generate Secret"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Secret Generated / Rotated Modal */}
      {generatedSecret && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50 fade-in">
          <div className="glass-card p-6 max-w-lg w-full border-[#00ff88]/30 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#00ff88]/10 border border-[#00ff88]/30 flex items-center justify-center shrink-0">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <div>
                <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
                  HMAC Webhook Signing Secret Generated
                </h2>
                <p className="text-xs text-[#7ba3c8]">For {secretAppName}</p>
              </div>
            </div>

            {/* Security Alert Banner */}
            <div className="p-3.5 rounded-xl border border-[#ffa502]/30 bg-[#ffa502]/10 text-xs text-[#ffa502] leading-relaxed">
              <strong>Security Notice:</strong> Copy this secret now. It is encrypted in our database and will <strong>never be shown again</strong>. Store it in your CI/CD repository secrets.
            </div>

            {/* Secret Display Box */}
            <div className="space-y-1.5">
              <div className="flex justify-between items-center text-xs">
                <span className="font-semibold text-[#4a6580] uppercase tracking-wider">
                  Signing Secret (HMAC-SHA256)
                </span>
                <button
                  onClick={() => setShowRawSecret(!showRawSecret)}
                  className="text-[#00d4ff] hover:underline"
                >
                  {showRawSecret ? "Hide" : "Reveal"}
                </button>
              </div>
              <div className="flex items-center gap-2 p-3 rounded-xl bg-[#080c14] border border-[#00d4ff]/20">
                <code className="flex-1 font-mono text-xs text-[#00ff88] break-all">
                  {showRawSecret ? generatedSecret : "•".repeat(48)}
                </code>
                <button
                  onClick={() => copyToClipboard(generatedSecret)}
                  className="btn-primary text-xs shrink-0"
                >
                  {copied ? "Copied!" : "Copy Secret"}
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setGeneratedSecret(null)}
                className="btn-secondary text-xs"
              >
                I Have Saved This Secret
              </button>
            </div>
          </div>
        </div>
      )}
    </AppLayout>
  );
}

