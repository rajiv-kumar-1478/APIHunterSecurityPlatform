"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { AppLayout } from "@/components/AppLayout";
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
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-[#7ba3c8] font-medium">Loading Security Center…</p>
        </div>
      </div>
    );
  }

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="Security Center"
      subtitle="Deterministic Risk Posture, Candidate Secrets Inventory & Automated Scans"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setActiveTab("scans")}
            className={`px-3 py-1.5 text-xs rounded-lg font-semibold transition-all ${
              activeTab === "scans"
                ? "bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/40 shadow-sm"
                : "bg-white/5 text-[#7ba3c8] border border-white/10 hover:text-white"
            }`}
          >
            🚀 Scans & Pipelines
          </button>
          <button
            onClick={() => setActiveTab("inventory")}
            className={`px-3 py-1.5 text-xs rounded-lg font-semibold transition-all ${
              activeTab === "inventory"
                ? "bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/40 shadow-sm"
                : "bg-white/5 text-[#7ba3c8] border border-white/10 hover:text-white"
            }`}
          >
            🛡️ Findings Inventory
          </button>
          <button
            onClick={() => setActiveTab("graph")}
            className={`px-3 py-1.5 text-xs rounded-lg font-semibold transition-all ${
              activeTab === "graph"
                ? "bg-[#00d4ff]/20 text-[#00d4ff] border border-[#00d4ff]/40 shadow-sm"
                : "bg-white/5 text-[#7ba3c8] border border-white/10 hover:text-white"
            }`}
          >
            🕸️ Security Graph
          </button>
        </div>
      }
    >
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
        <div className="fade-in space-y-4">
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

      {/* Tab 3: Bounded Security Graph View */}
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
    </AppLayout>
  );
}

