"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/Sidebar";
import {
  AlertingStatus,
  PagedResult,
  SecurityFinding,
  SecurityPosture,
  getAlertingStatus,
  getFindings,
  getSecurityPosture,
} from "@/lib/security-api";
import { SecurityPostureCard } from "@/components/SecurityPostureCard";
import { FindingFilters } from "@/components/FindingFilters";
import { FindingsTable } from "@/components/FindingsTable";
import { FindingDetailDrawer } from "@/components/FindingDetailDrawer";
import { SecurityGraphView } from "@/components/SecurityGraphView";
import { AlertingStatusCard } from "@/components/AlertingStatusCard";
import { ScanManagementView } from "@/components/ScanManagementView";

import { apiRequest } from "@/lib/api-client";

interface CurrentUser {
  isPlatformAdmin: boolean;
  userId: string;
  email?: string;
}

export default function SecurityCenterPage() {
  const router = useRouter();
  const [user, setUser] = useState<CurrentUser | null>(null);

  const [posture, setPosture] = useState<SecurityPosture | null>(null);
  const [alertingStatus, setAlertingStatus] = useState<AlertingStatus | null>(null);

  // Finding Inventory State
  const [severity, setSeverity] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [findingType, setFindingType] = useState<string>("");
  const [page, setPage] = useState<number>(1);
  const [findingsData, setFindingsData] = useState<PagedResult<SecurityFinding>>({
    items: [],
    totalCount: 0,
    page: 1,
    pageSize: 20,
  });
  const [loadingFindings, setLoadingFindings] = useState<boolean>(true);

  // Detail Drawer State
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);

  // Tab State: "scans" | "inventory" | "graph"
  const [activeTab, setActiveTab] = useState<"scans" | "inventory" | "graph">("scans");

  // Load User & Basic Metadata
  useEffect(() => {
    async function init() {
      try {
        const data = await apiRequest<CurrentUser>("/api/v1/auth/me");
        setUser(data);

        // Load posture and alerting status DTOs
        const [postureData, alertData] = await Promise.all([
          getSecurityPosture(),
          getAlertingStatus(),
        ]);
        setPosture(postureData);
        setAlertingStatus(alertData);
      } catch {
        router.replace("/login");
      }
    }
    init();
  }, [router]);

  // Load Findings Inventory
  const requestFindings = useCallback(
    () =>
      getFindings({
        severity: severity || undefined,
        status: status || undefined,
        findingType: findingType || undefined,
        page,
        pageSize: 20,
      }),
    [severity, status, findingType, page],
  );

  const loadFindingsList = useCallback(async () => {
    const data = await requestFindings();
    setFindingsData(data);
    setLoadingFindings(false);
  }, [requestFindings]);

  useEffect(() => {
    if (!user) return;

    let cancelled = false;
    void requestFindings().then((data) => {
      if (cancelled) return;
      setFindingsData(data);
      setLoadingFindings(false);
    });

    return () => {
      cancelled = true;
    };
  }, [user, requestFindings]);

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div
          className="w-8 h-8 border-2 border-current border-t-transparent rounded-full animate-spin"
          style={{ color: "var(--accent-cyan)" }}
        />
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar isAdmin={user.isPlatformAdmin} userEmail={user.email} />

      <main className="flex-1 overflow-auto p-8">
        {/* Header */}
        <div className="mb-6 fade-in flex items-center justify-between">
          <div>
            <h1
              className="text-3xl font-bold mb-1"
              style={{ fontFamily: "Outfit, sans-serif" }}
            >
              <span className="gradient-text">Security Center</span> Dashboard
            </h1>
            <p style={{ color: "var(--text-muted)", fontSize: "14px" }}>
              Phase 6 — Deterministic Risk Posture, Findings Inventory & Governance
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab("scans")}
              className={`px-4 py-2 text-xs rounded-lg font-semibold transition-all ${
                activeTab === "scans"
                  ? "bg-indigo-950 text-indigo-300 border border-indigo-700 shadow-lg"
                  : "bg-slate-900/60 text-muted border border-slate-800 hover:text-foreground"
              }`}
            >
              🚀 Scans & Pipelines
            </button>
            <button
              onClick={() => setActiveTab("inventory")}
              className={`px-4 py-2 text-xs rounded-lg font-semibold transition-all ${
                activeTab === "inventory"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-lg"
                  : "bg-slate-900/60 text-muted border border-slate-800 hover:text-foreground"
              }`}
            >
              🛡️ Findings Inventory
            </button>
            <button
              onClick={() => setActiveTab("graph")}
              className={`px-4 py-2 text-xs rounded-lg font-semibold transition-all ${
                activeTab === "graph"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-lg"
                  : "bg-slate-900/60 text-muted border border-slate-800 hover:text-foreground"
              }`}
            >
              🕸️ Security Graph
            </button>
          </div>
        </div>

        {/* Security Risk Posture Overview Cards */}
        <SecurityPostureCard posture={posture} />

        {/* Read-Only Alert Subsystem Status Card */}
        <AlertingStatusCard status={alertingStatus} />

        {/* Tab 1: Hosted Security Scans & Pipelines */}
        {activeTab === "scans" && (
          <div className="fade-in">
            <ScanManagementView />
          </div>
        )}

        {/* Tab 2: Findings Inventory Table & Filters */}
        {activeTab === "inventory" && (
          <div className="fade-in">
            <FindingFilters
              severity={severity}
              status={status}
              findingType={findingType}
              onSeverityChange={(sev) => {
                setLoadingFindings(true);
                setSeverity(sev);
                setPage(1);
              }}
              onStatusChange={(st) => {
                setLoadingFindings(true);
                setStatus(st);
                setPage(1);
              }}
              onTypeChange={(t) => {
                setLoadingFindings(true);
                setFindingType(t);
                setPage(1);
              }}
            />

            <FindingsTable
              data={findingsData}
              loading={loadingFindings}
              onPageChange={(nextPage) => {
                setLoadingFindings(true);
                setPage(nextPage);
              }}
              onSelectFinding={(f) => setSelectedFinding(f)}
            />
          </div>
        )}

        {/* Tab 2: Bounded Security Graph View */}
        {activeTab === "graph" && (
          <div className="fade-in">
            <SecurityGraphView />
          </div>
        )}

        {/* Side-Drawer for Finding Details & Governance */}
        <FindingDetailDrawer
          finding={selectedFinding}
          isAdmin={user.isPlatformAdmin}
          onClose={() => setSelectedFinding(null)}
          onRefreshFinding={async () => {
            await loadFindingsList();
            const postureData = await getSecurityPosture();
            setPosture(postureData);
            if (selectedFinding) {
              const updatedList = await getFindings({
                severity: severity || undefined,
                status: status || undefined,
                findingType: findingType || undefined,
                page,
                pageSize: 20,
              });
              const match = updatedList.items.find((item) => item.id === selectedFinding.id);
              if (match) setSelectedFinding(match);
            }
          }}
        />
      </main>
    </div>
  );
}
