"use client";

import { useEffect, useState, useCallback } from "react";
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

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetchRemediationActions(filters);
      setActions(res.actions);
      setSummary(res.summary);
    } catch (err: any) {
      setError(err.message || "Failed to load remediation center data");
    } finally {
      setIsLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSelectStatusCard = (statusKey: string) => {
    setFilters({ ...filters, status: statusKey || undefined, page: 1 });
  };

  const handleResetFilters = () => {
    setFilters({ page: 1, pageSize: 20 });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400 bg-indigo-950/60 px-2.5 py-0.5 rounded border border-indigo-800/40">
              Phase 7 Governance & Security Response
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Remediation Center
          </h1>
          <p className="text-xs md:text-sm text-slate-400 mt-1">
            Governance dashboard for deterministic security recommendations, approvals, execution tracking, and post-remediation verification.
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={isLoading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 text-xs font-semibold transition-all border border-slate-800 shadow-lg disabled:opacity-50"
        >
          <svg className={`w-4 h-4 text-indigo-400 ${isLoading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh Data
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-rose-950/40 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-center gap-3">
          <svg className="w-5 h-5 text-rose-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
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
        onChange={setFilters}
        onReset={handleResetFilters}
      />

      {/* Actions Data Table */}
      {isLoading ? (
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 rounded-xl p-16 text-center text-slate-500 text-xs">
          <div className="inline-block w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mb-3" />
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
        onRefreshList={loadData}
      />
    </div>
  );
}
