"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

interface PermissionDto {
  id: string;
  code: string;
  name: string;
  category: string;
  description: string;
}

interface FieldPermissionDto {
  id: string;
  permissionCode: string;
  resourceType: string;
  fieldName: string;
  action: string;
  effect: string;
}

export default function PermissionsPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean } | null>(null);
  const [permissions, setPermissions] = useState<PermissionDto[]>([]);
  const [fieldPermissions, setFieldPermissions] = useState<FieldPermissionDto[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function init() {
      const meRes = await fetch(`${API_URL}/api/v1/auth/me`, { credentials: "include" });
      if (!meRes.ok) { router.replace("/login"); return; }
      const me = await meRes.json();
      if (!me.isPlatformAdmin) { router.replace("/dashboard"); return; }
      setUser(me);

      const [pRes, fpRes] = await Promise.all([
        fetch(`${API_URL}/api/v1/admin/permissions`, { credentials: "include" }),
        fetch(`${API_URL}/api/v1/admin/field-permissions`, { credentials: "include" }),
      ]);

      if (pRes.ok) setPermissions(await pRes.json());
      if (fpRes.ok) setFieldPermissions(await fpRes.json());
      setLoading(false);
    }
    init();
  }, [router]);

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
            Permission Catalog & Field Level Rules
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
            Role-Based Access Control and Field Level Authorization Policies
          </p>
        </div>

        {/* Permission Catalog */}
        <div className="glass-card p-6 mb-8 fade-in">
          <h2 className="text-lg font-semibold mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>
            System Permissions
          </h2>
          {loading ? (
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>Loading permissions…</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {permissions.map((p) => (
                <div key={p.id} className="p-4 rounded-xl" style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-subtle)" }}>
                  <div className="flex items-center justify-between mb-1">
                    <p className="font-semibold text-sm" style={{ color: "var(--text-primary)" }}>{p.name}</p>
                    <span className="badge" style={{ background: "rgba(139,92,246,0.15)", color: "var(--accent-purple)" }}>{p.category}</span>
                  </div>
                  <p className="mono text-xs mb-2" style={{ color: "var(--accent-cyan)" }}>{p.code}</p>
                  <p className="text-xs" style={{ color: "var(--text-muted)" }}>{p.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Field Permissions */}
        <div className="glass-card p-6 fade-in">
          <h2 className="text-lg font-semibold mb-4" style={{ fontFamily: "Outfit, sans-serif" }}>
            Field Level Authorization Rules
          </h2>
          {fieldPermissions.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>No custom field-level restriction rules defined.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Permission Code</th>
                  <th>Resource</th>
                  <th>Field</th>
                  <th>Action</th>
                  <th>Effect</th>
                </tr>
              </thead>
              <tbody>
                {fieldPermissions.map(fp => (
                  <tr key={fp.id}>
                    <td className="mono">{fp.permissionCode}</td>
                    <td>{fp.resourceType}</td>
                    <td className="mono" style={{ color: "var(--accent-cyan)" }}>{fp.fieldName}</td>
                    <td>{fp.action}</td>
                    <td>
                      <span className={`badge ${fp.effect === "Allow" ? "badge-healthy" : "badge-unhealthy"}`}>
                        {fp.effect}
                      </span>
                    </td>
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
