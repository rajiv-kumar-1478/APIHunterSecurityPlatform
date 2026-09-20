"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
import { apiRequest } from "@/lib/api-client";

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
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; email?: string } | null>(null);
  const [permissions, setPermissions] = useState<PermissionDto[]>([]);
  const [fieldPermissions, setFieldPermissions] = useState<FieldPermissionDto[]>([]);
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

        const [permissionData, fieldPermissionData] = await Promise.all([
          apiRequest<PermissionDto[]>("/api/v1/admin/permissions"),
          apiRequest<FieldPermissionDto[]>("/api/v1/admin/field-permissions"),
        ]);

        setPermissions(permissionData);
        setFieldPermissions(fieldPermissionData);
        setLoading(false);
      } catch {
        router.replace("/login");
      }
    }
    void init();
  }, [router]);

  if (!user) return (
    <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
      <div className="flex flex-col items-center gap-3">
        <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
        <p className="text-xs text-[#7ba3c8] font-medium">Loading Permissions Catalog…</p>
      </div>
    </div>
  );

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="Permission Catalog & Field Rules"
      subtitle="Role-Based Access Control and Field Level Authorization Policies"
    >
      {/* Permission Catalog */}
      <div className="glass-card p-6 fade-in space-y-4">
        <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
          System Permissions Catalog
        </h2>
        {loading ? (
          <div className="p-8 text-center text-[#7ba3c8] text-xs">
            <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            Loading permissions catalog…
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {permissions.map((p) => (
              <div key={p.id} className="p-4 rounded-xl bg-[#080c14]/60 border border-[#00d4ff]/10 space-y-2">
                <div className="flex items-center justify-between">
                  <p className="font-bold text-sm text-[#e8f4ff]">{p.name}</p>
                  <span className="badge badge-admin text-[10px]">{p.category}</span>
                </div>
                <p className="font-mono text-xs text-[#00d4ff]">{p.code}</p>
                <p className="text-xs text-[#7ba3c8] leading-relaxed">{p.description}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Field Permissions */}
      <div className="glass-card p-6 fade-in space-y-4">
        <h2 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: "Outfit, sans-serif" }}>
          Field Level Authorization Rules
        </h2>
        {fieldPermissions.length === 0 ? (
          <p className="text-xs text-[#7ba3c8]">No custom field-level restriction rules defined.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[600px]">
              <thead>
                <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                  <th className="p-4">Permission Code</th>
                  <th className="p-4">Resource</th>
                  <th className="p-4">Field</th>
                  <th className="p-4">Action</th>
                  <th className="p-4">Effect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
                {fieldPermissions.map(fp => (
                  <tr key={fp.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4 font-mono text-[#00d4ff]">{fp.permissionCode}</td>
                    <td className="p-4 text-[#e8f4ff] font-medium">{fp.resourceType}</td>
                    <td className="p-4 font-mono text-[#00ff88]">{fp.fieldName}</td>
                    <td className="p-4 text-[#7ba3c8]">{fp.action}</td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 text-[10px] font-semibold rounded-full border ${
                        fp.effect === "Allow" ? "badge-healthy" : "badge-unhealthy"
                      }`}>
                        {fp.effect}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AppLayout>
  );
}

