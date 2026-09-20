"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";
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
      // Fallback
      alert("Please copy manually from the input.");
    }
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh", backgroundColor: "#0b0f19", color: "#f3f4f6" }}>
      <Sidebar isAdmin={user?.isPlatformAdmin ?? false} userEmail={user?.email} />
      <main style={{ flex: 1, padding: "2rem", maxWidth: "1280px", margin: "0 auto" }}>
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem" }}>
          <div>
            <h1 style={{ fontSize: "1.875rem", fontWeight: 700, margin: 0, color: "#fff" }}>
              CI/CD Deployment Applications
            </h1>
            <p style={{ color: "#9ca3af", marginTop: "0.5rem", fontSize: "0.95rem" }}>
              Manage registered applications, authorized target scan URLs, and HMAC-SHA256 signing keys for CI/CD deployment webhooks.
            </p>
          </div>
          <button
            id="btn-register-app"
            onClick={() => setShowRegisterModal(true)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              backgroundColor: "#2563eb",
              color: "#fff",
              border: "none",
              borderRadius: "0.5rem",
              padding: "0.625rem 1.25rem",
              fontWeight: 600,
              fontSize: "0.875rem",
              cursor: "pointer",
              transition: "background 0.2s ease",
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12h14" />
            </svg>
            Register Application
          </button>
        </div>

        {/* Notifications */}
        {error && (
          <div style={{ backgroundColor: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", borderRadius: "0.5rem", padding: "1rem", marginBottom: "1.5rem", color: "#fca5a5" }}>
            {error}
          </div>
        )}
        {actionSuccess && (
          <div style={{ backgroundColor: "rgba(34, 197, 94, 0.15)", border: "1px solid #22c55e", borderRadius: "0.5rem", padding: "1rem", marginBottom: "1.5rem", color: "#86efac" }}>
            {actionSuccess}
          </div>
        )}

        {/* Application List Table */}
        <div style={{ backgroundColor: "#111827", borderRadius: "0.75rem", border: "1px solid #1f2937", overflow: "hidden" }}>
          {loading ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "#9ca3af" }}>Loading applications...</div>
          ) : applications.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "#9ca3af" }}>
              <p style={{ margin: 0, fontSize: "1.1rem", fontWeight: 500 }}>No applications registered yet.</p>
              <p style={{ margin: "0.5rem 0 0 0", fontSize: "0.9rem" }}>
                Click &quot;Register Application&quot; to authorize a deployment target and generate an HMAC webhook secret.
              </p>
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #1f2937", backgroundColor: "#161e2e" }}>
                  <th style={{ padding: "1rem", color: "#9ca3af", fontWeight: 600, fontSize: "0.75rem", textTransform: "uppercase" }}>Application</th>
                  <th style={{ padding: "1rem", color: "#9ca3af", fontWeight: 600, fontSize: "0.75rem", textTransform: "uppercase" }}>App ID</th>
                  <th style={{ padding: "1rem", color: "#9ca3af", fontWeight: 600, fontSize: "0.75rem", textTransform: "uppercase" }}>Environment</th>
                  <th style={{ padding: "1rem", color: "#9ca3af", fontWeight: 600, fontSize: "0.75rem", textTransform: "uppercase" }}>Authorized Target URL</th>
                  <th style={{ padding: "1rem", color: "#9ca3af", fontWeight: 600, fontSize: "0.75rem", textTransform: "uppercase" }}>Status</th>
                  <th style={{ padding: "1rem", color: "#9ca3af", fontWeight: 600, fontSize: "0.75rem", textTransform: "uppercase" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {applications.map((app) => (
                  <tr key={app.id} style={{ borderBottom: "1px solid #1f2937" }}>
                    <td style={{ padding: "1rem", fontWeight: 600, color: "#fff" }}>{app.displayName}</td>
                    <td style={{ padding: "1rem" }}>
                      <code style={{ backgroundColor: "#1f2937", padding: "0.2rem 0.4rem", borderRadius: "0.25rem", fontSize: "0.85rem", color: "#60a5fa" }}>
                        {app.applicationId}
                      </code>
                    </td>
                    <td style={{ padding: "1rem" }}>
                      <span style={{
                        padding: "0.25rem 0.5rem",
                        borderRadius: "0.25rem",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        backgroundColor: app.environment.toLowerCase() === "production" ? "rgba(239, 68, 68, 0.2)" : "rgba(59, 130, 246, 0.2)",
                        color: app.environment.toLowerCase() === "production" ? "#fca5a5" : "#93c5fd",
                      }}>
                        {app.environment}
                      </span>
                    </td>
                    <td style={{ padding: "1rem" }}>
                      <span style={{ fontSize: "0.875rem", color: "#d1d5db" }}>{app.authorizedTargetUrl}</span>
                    </td>
                    <td style={{ padding: "1rem" }}>
                      <span style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "0.35rem",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        padding: "0.25rem 0.5rem",
                        borderRadius: "0.25rem",
                        backgroundColor: app.enabled ? "rgba(34, 197, 94, 0.2)" : "rgba(107, 114, 128, 0.2)",
                        color: app.enabled ? "#86efac" : "#9ca3af",
                      }}>
                        <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: app.enabled ? "#22c55e" : "#6b7280" }} />
                        {app.enabled ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td style={{ padding: "1rem" }}>
                      <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button
                          onClick={() => handleRegenerateSecret(app)}
                          title="Rotate Secret"
                          style={{
                            padding: "0.35rem 0.65rem",
                            borderRadius: "0.375rem",
                            border: "1px solid #374151",
                            backgroundColor: "#1f2937",
                            color: "#d1d5db",
                            fontSize: "0.75rem",
                            cursor: "pointer",
                          }}
                        >
                          Rotate Secret
                        </button>
                        <button
                          onClick={() => handleToggleStatus(app)}
                          style={{
                            padding: "0.35rem 0.65rem",
                            borderRadius: "0.375rem",
                            border: "1px solid #374151",
                            backgroundColor: "#1f2937",
                            color: app.enabled ? "#fca5a5" : "#86efac",
                            fontSize: "0.75rem",
                            cursor: "pointer",
                          }}
                        >
                          {app.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          onClick={() => handleDelete(app)}
                          title="Delete Application"
                          style={{
                            padding: "0.35rem 0.65rem",
                            borderRadius: "0.375rem",
                            border: "1px solid rgba(239, 68, 68, 0.4)",
                            backgroundColor: "rgba(239, 68, 68, 0.1)",
                            color: "#ef4444",
                            fontSize: "0.75rem",
                            cursor: "pointer",
                          }}
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

        {/* Integration Instructions Card */}
        <div style={{ marginTop: "2.5rem", backgroundColor: "#111827", borderRadius: "0.75rem", border: "1px solid #1f2937", padding: "1.5rem" }}>
          <h2 style={{ fontSize: "1.125rem", fontWeight: 600, color: "#fff", marginBottom: "0.75rem" }}>
            How to Connect Your CI/CD Pipeline
          </h2>
          <p style={{ fontSize: "0.9rem", color: "#9ca3af", marginBottom: "1rem" }}>
            When a deployment succeeds, send a webhook payload signed with your HMAC secret to enqueue an incremental verification scan.
          </p>
          <div style={{ backgroundColor: "#0b0f19", border: "1px solid #1f2937", borderRadius: "0.5rem", padding: "1rem", overflowX: "auto" }}>
            <pre style={{ margin: 0, fontSize: "0.825rem", color: "#93c5fd", fontFamily: "monospace" }}>
{`# 1. Prepare JSON body
PAYLOAD='{"applicationId":"YOUR_APP_ID","commitSha":"\${GITHUB_SHA}","branch":"main"}'
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 2. Compute HMAC-SHA256 signature
SIGNATURE="sha256=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "YOUR_HMAC_SECRET" | sed 's/^.* //')"

# 3. Deliver to APIHunter deployment webhook endpoint
curl -X POST https://api.yourdomain.com/api/v1/webhooks/deployments \\
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
          <div style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(0,0,0,0.75)",
            backdropFilter: "blur(4px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 50,
          }}>
            <div style={{
              backgroundColor: "#111827",
              border: "1px solid #374151",
              borderRadius: "0.75rem",
              width: "100%",
              maxWidth: "500px",
              padding: "1.75rem",
            }}>
              <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "#fff", marginBottom: "1rem" }}>
                Register CI/CD Application
              </h2>
              <form onSubmit={handleRegister}>
                <div style={{ marginBottom: "1rem" }}>
                  <label style={{ display: "block", fontSize: "0.85rem", color: "#d1d5db", marginBottom: "0.4rem" }}>
                    Application ID (Unique key used in webhooks) *
                  </label>
                  <input
                    id="input-app-id"
                    type="text"
                    required
                    placeholder="e.g. web-app-prod"
                    value={newAppId}
                    onChange={(e) => setNewAppId(e.target.value)}
                    style={{
                      width: "100%",
                      backgroundColor: "#1f2937",
                      border: "1px solid #374151",
                      borderRadius: "0.375rem",
                      padding: "0.6rem 0.75rem",
                      color: "#fff",
                      fontSize: "0.9rem",
                    }}
                  />
                </div>

                <div style={{ marginBottom: "1rem" }}>
                  <label style={{ display: "block", fontSize: "0.85rem", color: "#d1d5db", marginBottom: "0.4rem" }}>
                    Display Name
                  </label>
                  <input
                    id="input-display-name"
                    type="text"
                    placeholder="e.g. Core Web Application (Production)"
                    value={newDisplayName}
                    onChange={(e) => setNewDisplayName(e.target.value)}
                    style={{
                      width: "100%",
                      backgroundColor: "#1f2937",
                      border: "1px solid #374151",
                      borderRadius: "0.375rem",
                      padding: "0.6rem 0.75rem",
                      color: "#fff",
                      fontSize: "0.9rem",
                    }}
                  />
                </div>

                <div style={{ marginBottom: "1rem" }}>
                  <label style={{ display: "block", fontSize: "0.85rem", color: "#d1d5db", marginBottom: "0.4rem" }}>
                    Authorized Target URL (Server-controlled destination) *
                  </label>
                  <input
                    id="input-target-url"
                    type="url"
                    required
                    placeholder="https://api.mycompany.com"
                    value={newTargetUrl}
                    onChange={(e) => setNewTargetUrl(e.target.value)}
                    style={{
                      width: "100%",
                      backgroundColor: "#1f2937",
                      border: "1px solid #374151",
                      borderRadius: "0.375rem",
                      padding: "0.6rem 0.75rem",
                      color: "#fff",
                      fontSize: "0.9rem",
                    }}
                  />
                </div>

                <div style={{ marginBottom: "1.5rem" }}>
                  <label style={{ display: "block", fontSize: "0.85rem", color: "#d1d5db", marginBottom: "0.4rem" }}>
                    Environment
                  </label>
                  <select
                    value={newEnvironment}
                    onChange={(e) => setNewEnvironment(e.target.value)}
                    style={{
                      width: "100%",
                      backgroundColor: "#1f2937",
                      border: "1px solid #374151",
                      borderRadius: "0.375rem",
                      padding: "0.6rem 0.75rem",
                      color: "#fff",
                      fontSize: "0.9rem",
                    }}
                  >
                    <option value="Production">Production</option>
                    <option value="Staging">Staging</option>
                    <option value="QA">QA</option>
                    <option value="Development">Development</option>
                  </select>
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem" }}>
                  <button
                    type="button"
                    onClick={() => setShowRegisterModal(false)}
                    style={{
                      padding: "0.5rem 1rem",
                      borderRadius: "0.375rem",
                      border: "1px solid #374151",
                      backgroundColor: "transparent",
                      color: "#9ca3af",
                      cursor: "pointer",
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    style={{
                      padding: "0.5rem 1.25rem",
                      borderRadius: "0.375rem",
                      border: "none",
                      backgroundColor: "#2563eb",
                      color: "#fff",
                      fontWeight: 600,
                      cursor: submitting ? "not-allowed" : "pointer",
                    }}
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
          <div style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(0,0,0,0.85)",
            backdropFilter: "blur(6px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 60,
          }}>
            <div style={{
              backgroundColor: "#111827",
              border: "1px solid #22c55e",
              borderRadius: "0.75rem",
              width: "100%",
              maxWidth: "560px",
              padding: "1.75rem",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "1rem" }}>
                <div style={{ backgroundColor: "rgba(34, 197, 94, 0.2)", borderRadius: "50%", padding: "0.5rem" }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                </div>
                <div>
                  <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "#fff", margin: 0 }}>
                    HMAC Webhook Signing Secret Generated
                  </h2>
                  <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.85rem", color: "#9ca3af" }}>
                    For {secretAppName}
                  </p>
                </div>
              </div>

              {/* Security Alert Banner */}
              <div style={{
                backgroundColor: "rgba(245, 158, 11, 0.15)",
                border: "1px solid #f59e0b",
                borderRadius: "0.5rem",
                padding: "0.75rem 1rem",
                marginBottom: "1.25rem",
                fontSize: "0.85rem",
                color: "#fde68a",
              }}>
                <strong>Security Notice:</strong> Copy this secret now. It is encrypted in our database and will <strong>never be shown again</strong>. Store it in your CI/CD repository secrets (e.g. GitHub Actions Secrets).
              </div>

              {/* Secret Display Box */}
              <div style={{ marginBottom: "1.5rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.4rem" }}>
                  <span style={{ fontSize: "0.8rem", color: "#9ca3af", textTransform: "uppercase", fontWeight: 600 }}>
                    Signing Secret (HMAC-SHA256)
                  </span>
                  <button
                    onClick={() => setShowRawSecret(!showRawSecret)}
                    style={{ background: "none", border: "none", color: "#60a5fa", fontSize: "0.8rem", cursor: "pointer" }}
                  >
                    {showRawSecret ? "Hide" : "Reveal"}
                  </button>
                </div>
                <div style={{
                  display: "flex",
                  alignItems: "center",
                  backgroundColor: "#0b0f19",
                  border: "1px solid #374151",
                  borderRadius: "0.375rem",
                  padding: "0.5rem 0.75rem",
                  gap: "0.5rem",
                }}>
                  <code style={{
                    flex: 1,
                    fontFamily: "monospace",
                    fontSize: "0.85rem",
                    color: "#6ee7b7",
                    wordBreak: "break-all",
                  }}>
                    {showRawSecret ? generatedSecret : "•".repeat(48)}
                  </code>
                  <button
                    onClick={() => copyToClipboard(generatedSecret)}
                    style={{
                      backgroundColor: copied ? "#22c55e" : "#2563eb",
                      color: "#fff",
                      border: "none",
                      borderRadius: "0.25rem",
                      padding: "0.4rem 0.75rem",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                      transition: "background 0.2s",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {copied ? "Copied!" : "Copy Secret"}
                  </button>
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  onClick={() => setGeneratedSecret(null)}
                  style={{
                    backgroundColor: "#374151",
                    color: "#fff",
                    border: "none",
                    borderRadius: "0.375rem",
                    padding: "0.5rem 1.25rem",
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  I have saved this secret
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
