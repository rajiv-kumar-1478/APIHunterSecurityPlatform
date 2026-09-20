"use client";

import { useEffect, useState, useCallback } from "react";
import { AppLayout } from "@/components/AppLayout";
import { getErrorMessage } from "@/lib/api-client";
import {
  ActionFilterParams,
  RemediationActionListDto,
  RemediationSummary,
  fetchRemediationActions,
} from "@/lib/remediation-api";
import RemediationSummaryCards from "@/components/remediation/RemediationSummary";
import RemediationFilters from "@/components/remediation/RemediationFilters";
import RemediationTable from "@/components/remediation/RemediationTable";
import RemediationDetailDrawer from "@/components/remediation/RemediationDetailDrawer";

export default function RemediationCenterPage() {
  const [actions, setActions] = useState<RemediationActionListDto[]>([]);
  const [summary, setSummary] = useState<RemediationSummary | null>(null);
  const [filters, setFilters] = useState<ActionFilterParams>({ page: 1, pageSize: 20 });
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const requestData = useCallback(() => fetchRemediationActions(filters), [filters]);

  const loadData = useCallback(async () => {
    try {
      const res = await requestData();
      setActions(res.actions);
      setSummary(res.summary);
      setError(null);
    } catch (loadError: unknown) {
      setError(getErrorMessage(loadError, "Failed to load remediation center data"));
    } finally {
      setIsLoading(false);
    }
  }, [requestData]);

  useEffect(() => {
    let cancelled = false;
    void requestData()
      .then((res) => {
        if (cancelled) return;
        setActions(res.actions);
        setSummary(res.summary);
        setError(null);
      })
      .catch((loadError: unknown) => {
        if (!cancelled) {
          setError(getErrorMessage(loadError, "Failed to load remediation center data"));
        }
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [requestData]);

  const handleRefresh = () => {
    setIsLoading(true);
    setError(null);
    void loadData();
  };

  const handleSelectStatusCard = (statusKey: string) => {
    setIsLoading(true);
    setError(null);
    setFilters({ ...filters, status: statusKey || undefined, page: 1 });
  };

  const handleResetFilters = () => {
    setIsLoading(true);
    setError(null);
    setFilters({ page: 1, pageSize: 20 });
  };

  return (
    <AppLayout
      title="Remediation Center"
      subtitle="Deterministic policy recommendations, approval workflows & automated remediation execution"
      actions={
        <button
          onClick={handleRefresh}
          disabled={isLoading}
          className="btn-primary text-xs flex items-center gap-2"
        >
          <svg className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh Data
        </button>
      }
    >
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-xs text-red-400 flex items-center gap-3 fade-in">
          <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {error}
        </div>
      )}

      {/* Summary Cards */}
      <RemediationSummaryCards
        summary={summary}
        selectedStatus={filters.status ?? ""}
        onSelectStatus={handleSelectStatusCard}
      />

      {/* Filters Bar */}
      <RemediationFilters
        filters={filters}
        onChange={(nextFilters) => {
          setIsLoading(true);
          setError(null);
          setFilters(nextFilters);
        }}
        onReset={handleResetFilters}
      />

      {/* Actions Data Table */}
      {isLoading ? (
        <div className="glass-card p-12 text-center text-[#7ba3c8] text-xs">
          <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p>Loading remediation center actions...</p>
        </div>
      ) : (
        <RemediationTable
          actions={actions}
          onSelectAction={(action) => setSelectedActionId(action.id)}
        />
      )}

      {/* Action Detail Drawer */}
      <RemediationDetailDrawer
        actionId={selectedActionId}
        onClose={() => setSelectedActionId(null)}
        onRefreshList={handleRefresh}
      />
    </AppLayout>
  );
}

