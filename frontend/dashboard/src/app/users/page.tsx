"use client";

import { useEffect, useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
import { ApiError, apiRequest } from "@/lib/api-client";

interface CurrentUser {
  isPlatformAdmin: boolean;
  email?: string;
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
    <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
      <div className="flex flex-col items-center gap-3">
        <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
        <p className="text-xs text-[#7ba3c8] font-medium">Loading User Governance…</p>
      </div>
    </div>
  );

  return (
    <AppLayout
      isAdmin={currentUser.isPlatformAdmin}
      userEmail={currentUser.email}
      title="User Management"
      subtitle="Platform accounts, administrator credentials & RBAC access controls"
      actions={
        <button className="btn-primary text-xs flex items-center gap-2" onClick={() => setShowCreateModal(true)}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Create User
        </button>
      }
    >
      {/* User table */}
      <div className="glass-card overflow-hidden fade-in">
        <div className="overflow-x-auto">
          {loading ? (
            <div className="p-12 text-center text-[#7ba3c8] text-xs">
              <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              Loading users…
            </div>
          ) : (
            <table className="w-full text-left border-collapse min-w-[700px]">
              <thead>
                <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                  <th className="p-4">User</th>
                  <th className="p-4">Username</th>
                  <th className="p-4">Role</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Created</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
                {users.map(u => (
                  <tr key={u.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4">
                      <div>
                        <p className="font-bold text-[#e8f4ff]">{u.displayName}</p>
                        <p className="text-xs text-[#7ba3c8]">{u.email}</p>
                      </div>
                    </td>
                    <td className="p-4 font-mono text-xs text-[#00d4ff]">{u.username}</td>
                    <td className="p-4">
                      {u.isPlatformAdmin ? (
                        <span className="badge badge-admin text-[10px]">Platform Admin</span>
                      ) : (
                        <span className="badge badge-healthy text-[10px]">Standard User</span>
                      )}
                    </td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 text-[10px] font-semibold rounded-full border ${
                        u.isActive ? "badge-healthy" : "badge-unhealthy"
                      }`}>
                        {u.isActive ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td className="p-4 text-xs text-[#7ba3c8]">{new Date(u.createdAtUtc).toLocaleDateString()}</td>
                    <td className="p-4 text-right">
                      <button className="btn-secondary text-xs" onClick={() => toggleUserStatus(u)}>
                        {u.isActive ? "Disable" : "Enable"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50 fade-in">
          <div className="glass-card p-6 w-full max-w-md border-[#00d4ff]/30">
            <h2 className="text-lg font-bold text-[#e8f4ff] mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>Create New User</h2>
            {formError && <div className="mb-4 p-3 rounded-xl text-xs bg-[#ff4757]/10 border border-[#ff4757]/30 text-[#ff4757] font-semibold">{formError}</div>}
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">Email</label>
                <input type="email" required className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]" value={email} onChange={e => setEmail(e.target.value)} />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">Username</label>
                <input type="text" required className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]" value={username} onChange={e => setUsername(e.target.value)} />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">Display Name</label>
                <input type="text" required className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]" value={displayName} onChange={e => setDisplayName(e.target.value)} />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#7ba3c8] mb-1">Password</label>
                <input type="password" required className="w-full px-3 py-2 text-xs bg-[#080c14] border border-[#00d4ff]/20 rounded-xl text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]" value={password} onChange={e => setPassword(e.target.value)} />
              </div>
              <div className="flex items-center gap-2 pt-1">
                <input type="checkbox" id="adminCheck" checked={isAdmin} onChange={e => setIsAdmin(e.target.checked)} className="rounded bg-[#080c14] border-[#00d4ff]/30 text-[#00d4ff] focus:ring-0" />
                <label htmlFor="adminCheck" className="text-xs text-[#e8f4ff] font-medium">Grant Platform Administrator Permissions</label>
              </div>
              <div className="flex gap-3 pt-2">
                <button type="button" className="btn-secondary flex-1 text-xs" onClick={() => setShowCreateModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary flex-1 text-xs" disabled={formLoading}>{formLoading ? "Creating…" : "Create"}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </AppLayout>
  );
}

