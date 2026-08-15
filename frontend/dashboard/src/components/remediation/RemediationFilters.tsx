"use client";

import { ActionFilterParams } from "@/lib/remediation-api";

interface RemediationFiltersProps {
  filters: ActionFilterParams;
  onChange: (newFilters: ActionFilterParams) => void;
  onReset: () => void;
}

export default function RemediationFilters({ filters, onChange, onReset }: RemediationFiltersProps) {
  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 rounded-xl p-4 mb-6 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
      <div>
        <label className="block text-xs font-semibold text-slate-400 mb-1">Status</label>
        <select
          value={filters.status ?? ""}
          onChange={(e) => onChange({ ...filters, status: e.target.value || undefined, page: 1 })}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Statuses</option>
          <option value="Proposed">Proposed</option>
          <option value="PendingApproval">Pending Approval</option>
          <option value="Approved">Approved</option>
          <option value="Executing">Executing</option>
          <option value="VerificationPending">Verification Pending</option>
          <option value="Verified">Verified</option>
          <option value="VerificationFailed">Verification Failed</option>
          <option value="Rejected">Rejected</option>
          <option value="Failed">Failed</option>
        </select>
      </div>

      <div>
        <label className="block text-xs font-semibold text-slate-400 mb-1">Action Type</label>
        <select
          value={filters.actionType ?? ""}
          onChange={(e) => onChange({ ...filters, actionType: e.target.value || undefined, page: 1 })}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Action Types</option>
          <option value="RevokeCredential">Revoke Credential</option>
          <option value="RotateCredential">Rotate Credential</option>
          <option value="RestrictCredentialScope">Restrict Scope</option>
          <option value="RemoveCurrentExposure">Remove Current Exposure</option>
          <option value="RemoveHistoricalExposure">Remove Historical Exposure</option>
          <option value="DisableExposedService">Disable Exposed Service</option>
          <option value="InvestigateExposure">Investigate Exposure</option>
        </select>
      </div>

      <div>
        <label className="block text-xs font-semibold text-slate-400 mb-1">Provider</label>
        <select
          value={filters.provider ?? ""}
          onChange={(e) => onChange({ ...filters, provider: e.target.value || undefined, page: 1 })}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Providers</option>
          <option value="github">GitHub</option>
          <option value="aws">AWS</option>
          <option value="stripe">Stripe</option>
          <option value="openai">OpenAI</option>
        </select>
      </div>

      <div>
        <label className="block text-xs font-semibold text-slate-400 mb-1">Search</label>
        <input
          type="text"
          placeholder="Title, description, repo..."
          value={filters.search ?? ""}
          onChange={(e) => onChange({ ...filters, search: e.target.value || undefined, page: 1 })}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        />
      </div>

      <div className="flex items-end">
        <button
          onClick={onReset}
          className="w-full bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium py-1.5 rounded-lg transition-colors border border-slate-700"
        >
          Reset Filters
        </button>
      </div>
    </div>
  );
}
