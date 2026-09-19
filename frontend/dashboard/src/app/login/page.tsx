"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";

import { ApiError, apiRequest, ensureCsrfToken, primeCsrfToken, refreshCsrfToken } from "@/lib/api-client";

interface LoginResponse {
  userId: string;
  isPlatformAdmin: boolean;
  expiresAt: string;
  csrfToken?: string;
}

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await ensureCsrfToken();
      const data = await apiRequest<LoginResponse>("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (data.csrfToken) {
        primeCsrfToken(data.csrfToken);
      } else {
        await refreshCsrfToken();
      }

      router.push("/dashboard");
    } catch (error: unknown) {
      if (error instanceof ApiError) {
        setError(error.message || "Login failed. Check your credentials.");
      } else {
        setError("Unable to connect to the server. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      {/* Background decorations */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 60% 60% at 50% 0%, rgba(0,212,255,0.07) 0%, transparent 70%)",
        }}
      />

      <div className="w-full max-w-md fade-in">
        {/* Logo / title */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-5"
            style={{ background: "rgba(0,212,255,0.1)", border: "1px solid rgba(0,212,255,0.2)" }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z"
                fill="rgba(0,212,255,0.2)" stroke="#00d4ff" strokeWidth="1.5" />
              <path d="M9 12l2 2 4-4" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold mb-2 gradient-text"
            style={{ fontFamily: "Outfit, sans-serif" }}>
            APIHunter Platform
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Security Intelligence Dashboard
          </p>
        </div>

        {/* Login card */}
        <div className="glass-card p-8">
          <h2 className="text-xl font-semibold mb-6"
            style={{ fontFamily: "Outfit, sans-serif", color: "var(--text-primary)" }}>
            Sign In
          </h2>

          {error && (
            <div className="mb-5 p-3 rounded-lg text-sm"
              style={{ background: "rgba(255,71,87,0.1)", border: "1px solid rgba(255,71,87,0.25)", color: "#ff4757" }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium mb-2"
                style={{ color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.8px" }}>
                Email
              </label>
              <input
                id="email"
                type="email"
                className="input-field"
                placeholder="admin@yourdomain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
              />
            </div>

            <div>
              <label className="block text-xs font-medium mb-2"
                style={{ color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.8px" }}>
                Password
              </label>
              <input
                id="password"
                type="password"
                className="input-field"
                placeholder="••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
            </div>

            <button
              type="submit"
              className="btn-primary w-full mt-2"
              disabled={loading}
              style={{ opacity: loading ? 0.7 : 1 }}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  Signing in…
                </span>
              ) : "Sign In"}
            </button>
          </form>

          <p className="mt-6 text-xs text-center" style={{ color: "var(--text-muted)" }}>
            Protected by session cookie + CSRF token authentication
          </p>
        </div>
      </div>
    </main>
  );
}
