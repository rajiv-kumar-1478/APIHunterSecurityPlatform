"use client";

import { useState, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import Link from "next/link";
import { apiFetch, clearAuthClientState, getErrorMessage } from "@/lib/api-client";

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  adminOnly?: boolean;
}

const navItems: NavItem[] = [
  {
    label: "Dashboard",
    href: "/dashboard",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
  },
  {
    label: "Security Center",
    href: "/security",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
  {
    label: "Remediation",
    href: "/security/remediation",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    ),
  },
  {
    label: "APIHunter Data",
    href: "/apihunter",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
      </svg>
    ),
  },
  {
    label: "Credentials",
    href: "/credentials",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
  },
  {
    label: "Deployments",
    href: "/deployments",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" />
        <path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z" />
      </svg>
    ),
  },
  {
    label: "Users",
    href: "/users",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
        <circle cx="9" cy="7" r="4" />
      </svg>
    ),
    adminOnly: true,
  },
  {
    label: "Permissions",
    href: "/permissions",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    adminOnly: true,
  },
  {
    label: "Audit Log",
    href: "/audit",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
      </svg>
    ),
    adminOnly: true,
  },
  {
    label: "Health",
    href: "/health",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
    adminOnly: true,
  },
  {
    label: "Operations AI",
    href: "/operations",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
        <circle cx="12" cy="12" r="3" />
      </svg>
    ),
    adminOnly: true,
  },
  {
    label: "AI Providers",
    href: "/settings/ai",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
        <line x1="12" y1="22.08" x2="12" y2="12" />
      </svg>
    ),
    adminOnly: true,
  },
  {
    label: "Notifications",
    href: "/settings/notifications",
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 0 1-3.46 0" />
      </svg>
    ),
    adminOnly: true,
  },
];

interface AppLayoutProps {
  children: React.ReactNode;
  isAdmin?: boolean;
  userEmail?: string;
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
}

export function AppLayout({
  children,
  isAdmin = true,
  userEmail = "admin@apihunter.local",
  title,
  subtitle,
  actions,
}: AppLayoutProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close mobile drawer when route changes
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  const visibleItems = navItems.filter((item) => !item.adminOnly || isAdmin);

  async function handleLogout() {
    try {
      await apiFetch("/api/v1/auth/logout", { method: "POST" });
    } catch (error: unknown) {
      console.error(getErrorMessage(error, "Logout failed."));
    } finally {
      clearAuthClientState();
      router.push("/login");
    }
  }

  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-[#080c14] text-[#e8f4ff]">
      {/* ─── 1. Desktop Sidebar (Hidden on mobile < md) ─── */}
      <aside
        className="hidden md:flex flex-col w-64 h-screen sticky top-0 border-r p-5 z-20"
        style={{
          background: "rgba(8,12,20,0.85)",
          borderColor: "var(--border-subtle)",
          backdropFilter: "blur(20px)",
        }}
      >
        {/* Brand logo */}
        <div className="flex items-center gap-3 mb-8 px-2">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center shadow-lg"
            style={{
              background: "linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(139,92,246,0.2) 100%)",
              border: "1px solid rgba(0,212,255,0.3)",
              boxShadow: "0 0 20px rgba(0,212,255,0.15)",
            }}
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 2L2 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z"
                fill="rgba(0,212,255,0.25)"
                stroke="#00d4ff"
                strokeWidth="1.8"
              />
              <path d="M9 12l2 2 4-4" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          <div>
            <p
              className="text-base font-bold tracking-tight gradient-text"
              style={{ fontFamily: "Outfit, sans-serif" }}
            >
              APIHunter
            </p>
            <p className="text-xs text-[#4a6580] font-medium">Security Platform</p>
          </div>
        </div>

        {/* Desktop Navigation Links */}
        <nav className="flex-1 space-y-1 overflow-y-auto pr-1">
          {visibleItems.map((item) => {
            const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`nav-item ${isActive ? "active" : ""}`}
              >
                <span className={isActive ? "text-[#00d4ff]" : "text-[#7ba3c8]"}>{item.icon}</span>
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* User Footer */}
        <div className="mt-4 border-t pt-4" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="px-2 mb-3">
            <p className="text-xs font-semibold truncate text-[#e8f4ff]">{userEmail}</p>
            <div className="flex items-center gap-2 mt-1">
              {isAdmin && <span className="badge badge-admin text-[10px] py-0.5 px-2">Admin</span>}
              <span className="badge badge-healthy text-[10px] py-0.5 px-2">Online</span>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="nav-item w-full text-red-400 hover:text-red-300 hover:bg-red-500/10"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* ─── 2. Mobile Top Bar Header (Only visible on mobile < md) ─── */}
      <header
        className="md:hidden flex items-center justify-between p-4 sticky top-0 z-30 border-b"
        style={{
          background: "rgba(8,12,20,0.92)",
          borderColor: "var(--border-subtle)",
          backdropFilter: "blur(20px)",
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center"
            style={{
              background: "rgba(0,212,255,0.15)",
              border: "1px solid rgba(0,212,255,0.3)",
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 2L2 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z"
                fill="rgba(0,212,255,0.2)"
                stroke="#00d4ff"
                strokeWidth="1.8"
              />
            </svg>
          </div>
          <span className="font-bold text-lg gradient-text" style={{ fontFamily: "Outfit, sans-serif" }}>
            APIHunter
          </span>
        </div>

        {/* Mobile Menu Hamburger Button */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle Navigation Menu"
          className="p-2.5 rounded-xl border transition-colors"
          style={{
            background: "rgba(13,21,37,0.8)",
            borderColor: "var(--border-subtle)",
            color: "#00d4ff",
          }}
        >
          {mobileOpen ? (
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          ) : (
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="3" y1="6" x2="21" y2="6" />
              <line x1="3" y1="12" x2="21" y2="12" />
              <line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          )}
        </button>
      </header>

      {/* ─── 3. Mobile Slide-Over Navigation Drawer ─── */}
      {mobileOpen && (
        <div className="md:hidden fixed inset-0 z-40 flex">
          {/* Backdrop Overlay */}
          <div
            className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
            onClick={() => setMobileOpen(false)}
          />

          {/* Slide-out Drawer Panel */}
          <aside
            className="relative flex flex-col w-72 max-w-[80vw] h-full p-5 border-r z-50 overflow-y-auto"
            style={{
              background: "#0d1525",
              borderColor: "var(--border-strong)",
              boxShadow: "0 0 40px rgba(0,212,255,0.2)",
            }}
          >
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-[#00d4ff]/15">
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg text-[#00d4ff]">Navigation</span>
              </div>
              <button
                onClick={() => setMobileOpen(false)}
                className="text-[#7ba3c8] hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <nav className="flex-1 space-y-1">
              {visibleItems.map((item) => {
                const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileOpen(false)}
                    className={`nav-item ${isActive ? "active" : ""}`}
                  >
                    <span className={isActive ? "text-[#00d4ff]" : "text-[#7ba3c8]"}>{item.icon}</span>
                    <span>{item.label}</span>
                  </Link>
                );
              })}
            </nav>

            <div className="mt-6 border-t pt-4 border-[#00d4ff]/15">
              <p className="text-xs text-[#e8f4ff] font-medium truncate mb-2">{userEmail}</p>
              <button
                onClick={() => {
                  setMobileOpen(false);
                  handleLogout();
                }}
                className="nav-item w-full text-red-400 hover:text-red-300 hover:bg-red-500/10"
              >
                <span>Sign Out</span>
              </button>
            </div>
          </aside>
        </div>
      )}

      {/* ─── 4. Main Page Area ─── */}
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Optional Page Top Header Bar */}
        {(title || actions) && (
          <div
            className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 sm:p-6 lg:p-8 border-b"
            style={{
              borderColor: "var(--border-subtle)",
              background: "rgba(13,21,37,0.4)",
            }}
          >
            <div>
              {title && (
                <h1
                  className="text-2xl sm:text-3xl font-bold tracking-tight gradient-text"
                  style={{ fontFamily: "Outfit, sans-serif" }}
                >
                  {title}
                </h1>
              )}
              {subtitle && <p className="text-xs sm:text-sm text-[#7ba3c8] mt-1">{subtitle}</p>}
            </div>

            {actions && <div className="flex flex-wrap items-center gap-3">{actions}</div>}
          </div>
        )}

        {/* Main Content Body */}
        <div className="flex-1 p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl w-full mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
