"use client";

import { useEffect, useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

import { ApiError, apiRequest } from "@/lib/api-client";

interface CurrentUser {
  isPlatformAdmin: boolean;
}

interface UserListResponse {
  items?: UserDto[];
}

interface UserDto {
  id: string;
  email: string;
  username: string;
  displayName: string;
  isPlatformAdmin: boolean;
  isActive: boolean;
  createdAtUtc: string;
  lastLoginAtUtc?: string;
}

export default function UsersPage() {
  const router = useRouter();
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [users, setUsers] = useState<UserDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // New user form state
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [formError, setFormError] = useState("");
  const [formLoading, setFormLoading] = useState(false);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiRequest<CurrentUser>("/api/v1/auth/me");
        if (!me.isPlatformAdmin) {
          router.replace("/dashboard");
          return;
        }
        setCurrentUser(me);
        await loadUsers();
      } catch {
        router.replace("/login");
      }
    }
    void init();
  }, [router]);

  async function loadUsers() {
    setLoading(true);
    try {
      const data = await apiRequest<UserListResponse>("/api/v1/users?page=1&pageSize=50");
      setUsers(data.items ?? []);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreateUser(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setFormLoading(true);
    try {
      await apiRequest<unknown>("/api/v1/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, username, displayName, password, isPlatformAdmin: isAdmin }),
      });

      setShowCreateModal(false);
      setEmail(""); setUsername(""); setDisplayName(""); setPassword(""); setIsAdmin(false);
      await loadUsers();
    } catch (error: unknown) {
      setFormError(error instanceof ApiError ? error.message : "Network error occurred.");
    } finally {
      setFormLoading(false);
    }
  }

  async function toggleUserStatus(user: UserDto) {
    try {
      await apiRequest<unknown>(`/api/v1/users/${user.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          displayName: user.displayName,
          isActive: !user.isActive,
          isPlatformAdmin: user.isPlatformAdmin,
        }),
      });
    } finally {
      await loadUsers();
    }
  }

  if (!currentUser) return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-8 h-8 border-2 border-current border-t-transparent rounded-full animate-spin"
        style={{ color: "var(--accent-cyan)" }} />
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar isAdmin={currentUser.isPlatformAdmin} />
      <main className="flex-1 overflow-auto p-8">
        <div className="flex items-center justify-between mb-8 fade-in">
          <div>
            <h1 className="text-2xl font-bold" style={{ fontFamily: "Outfit, sans-serif" }}>
              User Management
            </h1>
            <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
              Platform Users & Admin Accounts
            </p>
          </div>
          <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
            + Create User
          </button>
        </div>

        {/* User table */}
        <div className="glass-card overflow-hidden fade-in">
          {loading ? (
            <div className="p-8 text-center" style={{ color: "var(--text-muted)" }}>Loading users…</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td>
                      <div>
                        <p className="font-medium" style={{ color: "var(--text-primary)" }}>{u.displayName}</p>
                        <p className="text-xs" style={{ color: "var(--text-muted)" }}>{u.email}</p>
                      </div>
                    </td>
                    <td className="mono">{u.username}</td>
                    <td>
                      {u.isPlatformAdmin ? (
                        <span className="badge badge-admin">Admin</span>
                      ) : (
                        <span className="badge" style={{ background: "rgba(0,212,255,0.1)", color: "var(--accent-cyan)" }}>
                          User
                        </span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${u.isActive ? "badge-healthy" : "badge-unhealthy"}`}>
                        {u.isActive ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td className="text-xs">{new Date(u.createdAtUtc).toLocaleDateString()}</td>
                    <td>
                      <button className="btn-ghost text-xs" onClick={() => toggleUserStatus(u)}>
                        {u.isActive ? "Disable" : "Enable"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Create Modal */}
        {showCreateModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <div className="glass-card p-6 w-full max-w-md fade-in">
              <h2 className="text-lg font-bold mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>Create New User</h2>
              {formError && <div className="mb-4 p-3 rounded-lg text-xs" style={{ background: "rgba(255,71,87,0.15)", color: "#ff4757" }}>{formError}</div>}
              <form onSubmit={handleCreateUser} className="space-y-4">
                <div>
                  <label className="block text-xs text-muted mb-1">Email</label>
                  <input type="email" required className="input-field" value={email} onChange={e => setEmail(e.target.value)} />
                </div>
                <div>
                  <label className="block text-xs text-muted mb-1">Username</label>
                  <input type="text" required className="input-field" value={username} onChange={e => setUsername(e.target.value)} />
                </div>
                <div>
                  <label className="block text-xs text-muted mb-1">Display Name</label>
                  <input type="text" required className="input-field" value={displayName} onChange={e => setDisplayName(e.target.value)} />
                </div>
                <div>
                  <label className="block text-xs text-muted mb-1">Password</label>
                  <input type="password" required className="input-field" value={password} onChange={e => setPassword(e.target.value)} />
                </div>
                <div className="flex items-center gap-2">
                  <input type="checkbox" id="adminCheck" checked={isAdmin} onChange={e => setIsAdmin(e.target.checked)} />
                  <label htmlFor="adminCheck" className="text-xs" style={{ color: "var(--text-primary)" }}>Platform Administrator</label>
                </div>
                <div className="flex gap-3 pt-2">
                  <button type="button" className="btn-ghost flex-1" onClick={() => setShowCreateModal(false)}>Cancel</button>
                  <button type="submit" className="btn-primary flex-1" disabled={formLoading}>{formLoading ? "Creating…" : "Create"}</button>
                </div>
              </form>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
