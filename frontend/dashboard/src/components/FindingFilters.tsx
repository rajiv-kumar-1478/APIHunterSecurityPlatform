"use client";

interface FindingFiltersProps {
  severity: string;
  status: string;
  findingType: string;
  onSeverityChange: (sev: string) => void;
  onStatusChange: (st: string) => void;
  onTypeChange: (type: string) => void;
}

export function FindingFilters({
  severity,
  status,
  findingType,
  onSeverityChange,
  onStatusChange,
  onTypeChange,
}: FindingFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-3 mb-4 p-3 glass-card">
      <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mr-1">
        Filter By:
      </span>

      {/* Severity Filter */}
      <select
        value={severity}
        onChange={(e) => onSeverityChange(e.target.value)}
        className="px-3 py-1.5 text-xs rounded border bg-background text-foreground"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <option value="">All Severities</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
      </select>

      {/* Status Filter */}
      <select
        value={status}
        onChange={(e) => onStatusChange(e.target.value)}
        className="px-3 py-1.5 text-xs rounded border bg-background text-foreground"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <option value="">All Statuses</option>
        <option value="Open">Open</option>
        <option value="Investigating">Investigating</option>
        <option value="Confirmed">Confirmed</option>
        <option value="Remediated">Remediated</option>
        <option value="AcceptedRisk">Accepted Risk</option>
        <option value="FalsePositive">False Positive</option>
        <option value="Resolved">Resolved</option>
      </select>

      {/* Finding Type Filter */}
      <select
        value={findingType}
        onChange={(e) => onTypeChange(e.target.value)}
        className="px-3 py-1.5 text-xs rounded border bg-background text-foreground"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <option value="">All Finding Types</option>
        <option value="ValidatedCredentialExposed">Validated Credential Exposed</option>
        <option value="ExpiredCredentialExposed">Expired Credential Exposed</option>
        <option value="RevokedCredentialExposed">Revoked Credential Exposed</option>
        <option value="UnverifiedSecretCandidate">Unverified Secret Candidate</option>
        <option value="AuthenticationBypassRisk">Authentication Bypass Risk</option>
        <option value="InfrastructureSecretExposed">Infrastructure Secret Exposed</option>
      </select>

      {(severity || status || findingType) && (
        <button
          onClick={() => {
            onSeverityChange("");
            onStatusChange("");
            onTypeChange("");
          }}
          className="text-xs px-2 py-1 rounded text-red-400 hover:underline ml-auto"
        >
          Reset Filters
        </button>
      )}
    </div>
  );
}
