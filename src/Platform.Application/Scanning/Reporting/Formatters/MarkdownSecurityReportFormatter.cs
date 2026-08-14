using System;
using System.Linq;
using System.Text;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Reporting.Formatters;

/// <summary>
/// Projects the canonical report into clean, developer-friendly GitHub Flavored Markdown format.
/// Invariant: Finding-controlled text is sanitized and safely rendered.
/// </summary>
public class MarkdownSecurityReportFormatter : ISecurityReportFormatter
{
    public SecurityReportFormat Format => SecurityReportFormat.Markdown;
    public string ContentType => "text/markdown";
    public string FileExtension => "md";

    public FormattedReportResult FormatReport(CanonicalSecurityReport report)
    {
        var sb = new StringBuilder();
        var meta = report.Metadata;
        var posture = report.PostureSummary;
        var summary = report.ScanSummary;

        sb.AppendLine($"# Security Assessment Report — {EscapeMarkdown(meta.RepositoryName)}");
        sb.AppendLine();
        sb.AppendLine($"> **Target:** `{EscapeMarkdown(meta.TargetUrl)}`  ");
        sb.AppendLine($"> **Scan Job ID:** `{meta.ScanJobId}`  ");
        sb.AppendLine($"> **Scan Profile:** `{meta.ScanProfile}` | **Status:** `{meta.JobStatus}`  ");
        sb.AppendLine($"> **Assessment Completed:** `{meta.CompletedAtUtc:yyyy-MM-dd HH:mm:ss} UTC` (Duration: `{meta.DurationMs / 1000.0:F1}s`)");
        sb.AppendLine();

        // 1. Executive Summary
        sb.AppendLine("## 1. Executive Posture Summary");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|---|---|");
        sb.AppendLine($"| **Aggregate Risk Score** | **`{posture.AggregateRiskScore:F1}/100`** ({posture.RiskRating}) |");
        sb.AppendLine($"| **Total Findings** | **{posture.TotalFindings}** |");
        sb.AppendLine($"| **Critical Severity** | {posture.CriticalCount} |");
        sb.AppendLine($"| **High Severity** | {posture.HighCount} |");
        sb.AppendLine($"| **Medium Severity** | {posture.MediumCount} |");
        sb.AppendLine($"| **Low / Info** | {posture.LowCount + posture.InfoCount} |");
        sb.AppendLine();

        // 2. OWASP Top 10 Distribution
        if (posture.OwaspTop10Distribution.Any())
        {
            sb.AppendLine("### OWASP Top 10 Category Distribution");
            sb.AppendLine();
            sb.AppendLine("| Category | Count |");
            sb.AppendLine("|---|---|");
            foreach (var kvp in posture.OwaspTop10Distribution.OrderByDescending(k => k.Value))
            {
                sb.AppendLine($"| `{EscapeMarkdown(kvp.Key)}` | {kvp.Value} |");
            }
            sb.AppendLine();
        }

        // 3. Scan History & Diff Analysis
        if (report.ScanDiff != null)
        {
            var diff = report.ScanDiff;
            sb.AppendLine("## 2. Scan Baseline Comparison (Diff)");
            sb.AppendLine();
            sb.AppendLine($"- **New Findings Discovered (+):** {diff.NewFindings.Count}");
            sb.AppendLine($"- **Persistent Open Findings (=):** {diff.PersistentFindings.Count}");
            sb.AppendLine($"- **Not Observed in Current Scan (?):** {diff.NotObservedFindings.Count}");
            sb.AppendLine($"- **Confirmed Resolved Findings (✓):** {diff.ResolvedFindings.Count}");
            sb.AppendLine();
        }

        // 4. Detailed Findings
        sb.AppendLine("## 3. Vulnerability Findings Detail");
        sb.AppendLine();

        if (!report.Findings.Any())
        {
            sb.AppendLine("*No security vulnerabilities were detected in this assessment.*");
            sb.AppendLine();
        }
        else
        {
            int index = 1;
            foreach (var f in report.Findings)
            {
                sb.AppendLine($"### 3.{index} [{f.Severity}] {EscapeMarkdown(f.Title)}");
                sb.AppendLine();
                sb.AppendLine($"- **Type:** `{f.FindingType}` | **Risk Score:** `{f.RiskScore:F1}` | **Confidence:** `{f.Confidence}`");
                sb.AppendLine($"- **Fingerprint:** `{f.FindingFingerprint}`");
                if (f.CveList.Any()) sb.AppendLine($"- **CVE(s):** {string.Join(", ", f.CveList.Select(c => $"`{c}`"))}");
                if (f.CweList.Any()) sb.AppendLine($"- **CWE(s):** {string.Join(", ", f.CweList.Select(c => $"`{c}`"))}");
                sb.AppendLine();
                sb.AppendLine($"**Description:**  ");
                sb.AppendLine($"{EscapeMarkdown(f.Description)}");
                sb.AppendLine();

                if (f.SanitizedEvidences.Any())
                {
                    sb.AppendLine("**Evidence & Reproduction Artifacts (Sanitized):**");
                    sb.AppendLine();
                    foreach (var ev in f.SanitizedEvidences)
                    {
                        sb.AppendLine($"*Reference:* `{EscapeMarkdown(ev.EvidenceReference)}`");
                        sb.AppendLine("```json");
                        sb.AppendLine(ev.SafeEvidenceJson);
                        sb.AppendLine("```");
                        sb.AppendLine();
                    }
                }

                if (f.RecommendedRemediation != null)
                {
                    var rem = f.RecommendedRemediation;
                    sb.AppendLine("**Phase 7 Remediation Recommendation:**");
                    sb.AppendLine();
                    sb.AppendLine($"- **Action Type:** `{rem.ActionType}` (Status: `{rem.Status}`)");
                    sb.AppendLine($"- **Recommendation:** {EscapeMarkdown(rem.Title)}");
                    if (!string.IsNullOrWhiteSpace(rem.Description))
                    {
                        sb.AppendLine($"- **Guidance:** {EscapeMarkdown(rem.Description)}");
                    }
                    sb.AppendLine();
                }

                sb.AppendLine("---");
                sb.AppendLine();
                index++;
            }
        }

        // 5. Provenance & Integrity Watermark
        sb.AppendLine("## 4. Execution Provenance & Integrity");
        sb.AppendLine();
        sb.AppendLine($"- **Signature Version:** `{meta.SignatureVersion}`");
        sb.AppendLine($"- **Tool Coverage Hash:** `{meta.ToolCoverageHash}`");
        sb.AppendLine($"- **Provenance Watermark (SHA-256):** `{meta.ProvenanceSignature}`");
        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine("*Generated automatically by APIHunter Platform.*");

        var fileName = $"security-scan-report-{meta.ScanJobId:N}.md";
        return new FormattedReportResult(sb.ToString(), ContentType, fileName);
    }

    private static string EscapeMarkdown(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        return input.Replace("<", "&lt;").Replace(">", "&gt;").Replace("|", "\\|");
    }
}
