using System;
using System.Linq;
using System.Net;
using System.Text;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Reporting.Formatters;

/// <summary>
/// Projects the canonical report into a self-contained, print-ready executive HTML document.
/// Invariant: All user/finding-controlled strings are strictly HTML-encoded to prevent XSS.
/// </summary>
public class HtmlSecurityReportFormatter : ISecurityReportFormatter
{
    public SecurityReportFormat Format => SecurityReportFormat.Html;
    public string ContentType => "text/html; charset=utf-8";
    public string FileExtension => "html";

    public FormattedReportResult FormatReport(CanonicalSecurityReport report)
    {
        var meta = report.Metadata;
        var posture = report.PostureSummary;
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"  <title>Security Assessment Report - {H(meta.RepositoryName)}</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    :root { --bg: #0d1117; --card-bg: #161b22; --border: #30363d; --text: #c9d1d9; --text-muted: #8b949e; --accent: #58a6ff; --crit: #ff4d4f; --high: #fa8c16; --med: #e6a23c; --low: #52c41a; --info: #1890ff; }");
        sb.AppendLine("    @media print { body { background: #fff !important; color: #000 !important; } .card { border: 1px solid #ddd !important; background: #fff !important; } }");
        sb.AppendLine("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.6; }");
        sb.AppendLine("    .container { max-width: 1000px; margin: 0 auto; }");
        sb.AppendLine("    .header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }");
        sb.AppendLine("    .title { font-size: 2rem; font-weight: 700; color: #fff; margin: 0 0 0.5rem 0; }");
        sb.AppendLine("    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem; font-size: 0.9rem; color: var(--text-muted); }");
        sb.AppendLine("    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }");
        sb.AppendLine("    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-top: 1rem; text-align: center; }");
        sb.AppendLine("    .metric-box { background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; }");
        sb.AppendLine("    .metric-value { font-size: 1.8rem; font-weight: 700; }");
        sb.AppendLine("    .metric-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem; }");
        sb.AppendLine("    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }");
        sb.AppendLine("    .badge-critical { background: rgba(255,77,79,0.2); color: var(--crit); border: 1px solid var(--crit); }");
        sb.AppendLine("    .badge-high { background: rgba(250,140,22,0.2); color: var(--high); border: 1px solid var(--high); }");
        sb.AppendLine("    .badge-medium { background: rgba(230,162,60,0.2); color: var(--med); border: 1px solid var(--med); }");
        sb.AppendLine("    .badge-low { background: rgba(82,196,26,0.2); color: var(--low); border: 1px solid var(--low); }");
        sb.AppendLine("    .badge-info { background: rgba(24,144,255,0.2); color: var(--info); border: 1px solid var(--info); }");
        sb.AppendLine("    .finding-card { border-left: 4px solid var(--border); margin-bottom: 1rem; }");
        sb.AppendLine("    .finding-critical { border-left-color: var(--crit); }");
        sb.AppendLine("    .finding-high { border-left-color: var(--high); }");
        sb.AppendLine("    .finding-medium { border-left-color: var(--med); }");
        sb.AppendLine("    .finding-low { border-left-color: var(--low); }");
        sb.AppendLine("    .finding-info { border-left-color: var(--info); }");
        sb.AppendLine("    pre { background: #000; padding: 1rem; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 0.85rem; color: #a5d6ff; }");
        sb.AppendLine("    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }");
        sb.AppendLine("    th, td { border: 1px solid var(--border); padding: 0.75rem; text-align: left; }");
        sb.AppendLine("    th { background: rgba(255,255,255,0.05); }");
        sb.AppendLine("    .watermark { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--text-muted); text-align: center; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"container\">");

        // Header
        sb.AppendLine("    <div class=\"header\">");
        sb.AppendLine($"      <h1 class=\"title\">Security Assessment Report</h1>");
        sb.AppendLine($"      <div style=\"font-size: 1.1rem; color: var(--accent);\">{H(meta.RepositoryName)} &bull; {H(meta.TargetUrl)}</div>");
        sb.AppendLine("      <div class=\"meta-grid\">");
        sb.AppendLine($"        <div><strong>Scan Job:</strong> {meta.ScanJobId}</div>");
        sb.AppendLine($"        <div><strong>Profile:</strong> {meta.ScanProfile}</div>");
        sb.AppendLine($"        <div><strong>Status:</strong> {meta.JobStatus}</div>");
        sb.AppendLine($"        <div><strong>Completed:</strong> {meta.CompletedAtUtc:yyyy-MM-dd HH:mm:ss} UTC</div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // Executive Posture Card
        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <h2 style=\"margin-top:0;\">1. Executive Posture Summary</h2>");
        sb.AppendLine("      <div class=\"metrics-grid\">");
        sb.AppendLine($"        <div class=\"metric-box\"><div class=\"metric-value\" style=\"color:var(--crit);\">{posture.AggregateRiskScore:F1}</div><div class=\"metric-label\">Risk Score / 100</div></div>");
        sb.AppendLine($"        <div class=\"metric-box\"><div class=\"metric-value\">{posture.TotalFindings}</div><div class=\"metric-label\">Total Findings</div></div>");
        sb.AppendLine($"        <div class=\"metric-box\"><div class=\"metric-value\" style=\"color:var(--crit);\">{posture.CriticalCount}</div><div class=\"metric-label\">Critical</div></div>");
        sb.AppendLine($"        <div class=\"metric-box\"><div class=\"metric-value\" style=\"color:var(--high);\">{posture.HighCount}</div><div class=\"metric-label\">High</div></div>");
        sb.AppendLine($"        <div class=\"metric-box\"><div class=\"metric-value\" style=\"color:var(--med);\">{posture.MediumCount}</div><div class=\"metric-label\">Medium</div></div>");
        sb.AppendLine($"        <div class=\"metric-box\"><div class=\"metric-value\" style=\"color:var(--low);\">{posture.LowCount + posture.InfoCount}</div><div class=\"metric-label\">Low / Info</div></div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        // OWASP Distribution
        if (posture.OwaspTop10Distribution.Any())
        {
            sb.AppendLine("    <div class=\"card\">");
            sb.AppendLine("      <h2 style=\"margin-top:0;\">2. OWASP Top 10 Category Distribution</h2>");
            sb.AppendLine("      <table>");
            sb.AppendLine("        <thead><tr><th>Category</th><th style=\"width:100px;\">Findings</th></tr></thead>");
            sb.AppendLine("        <tbody>");
            foreach (var kvp in posture.OwaspTop10Distribution.OrderByDescending(k => k.Value))
            {
                sb.AppendLine($"          <tr><td>{H(kvp.Key)}</td><td><strong>{kvp.Value}</strong></td></tr>");
            }
            sb.AppendLine("        </tbody>");
            sb.AppendLine("      </table>");
            sb.AppendLine("    </div>");
        }

        // Findings Detail
        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <h2 style=\"margin-top:0;\">3. Vulnerability Findings Detail</h2>");

        if (!report.Findings.Any())
        {
            sb.AppendLine("      <p style=\"color:var(--text-muted);\">No security vulnerabilities were detected in this assessment.</p>");
        }
        else
        {
            foreach (var f in report.Findings)
            {
                var badgeClass = $"badge-{f.Severity.ToString().ToLowerInvariant()}";
                var borderClass = $"finding-{f.Severity.ToString().ToLowerInvariant()}";

                sb.AppendLine($"      <div class=\"card finding-card {borderClass}\">");
                sb.AppendLine($"        <div style=\"display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;\">");
                sb.AppendLine($"          <h3 style=\"margin:0; font-size:1.2rem;\">{H(f.Title)}</h3>");
                sb.AppendLine($"          <span class=\"badge {badgeClass}\">{f.Severity}</span>");
                sb.AppendLine("        </div>");
                sb.AppendLine($"        <p style=\"color:var(--text-muted); font-size:0.9rem; margin-bottom:1rem;\">{H(f.Description)}</p>");
                sb.AppendLine($"        <div style=\"font-size:0.85rem; margin-bottom:0.75rem;\">");
                sb.AppendLine($"          <strong>Type:</strong> {f.FindingType} &bull; <strong>Risk:</strong> {f.RiskScore:F1} &bull; <strong>Fingerprint:</strong> <code>{f.FindingFingerprint}</code>");
                sb.AppendLine("        </div>");

                if (f.SanitizedEvidences.Any())
                {
                    sb.AppendLine("        <div style=\"margin-top:0.75rem;\">");
                    sb.AppendLine("          <strong>Sanitized Evidence:</strong>");
                    foreach (var ev in f.SanitizedEvidences)
                    {
                        sb.AppendLine($"          <div style=\"font-size:0.8rem; color:var(--text-muted); margin-top:0.25rem;\">Ref: {H(ev.EvidenceReference)}</div>");
                        sb.AppendLine($"          <pre>{H(ev.SafeEvidenceJson)}</pre>");
                    }
                    sb.AppendLine("        </div>");
                }

                if (f.RecommendedRemediation != null)
                {
                    sb.AppendLine("        <div style=\"background:rgba(88,166,255,0.08); border:1px solid rgba(88,166,255,0.2); border-radius:6px; padding:0.75rem; margin-top:0.75rem;\">");
                    sb.AppendLine($"          <strong style=\"color:var(--accent);\">Recommended Remediation ({f.RecommendedRemediation.ActionType}):</strong> {H(f.RecommendedRemediation.Title)}");
                    if (!string.IsNullOrWhiteSpace(f.RecommendedRemediation.Description))
                    {
                        sb.AppendLine($"          <div style=\"font-size:0.85rem; margin-top:0.25rem; color:var(--text);\">{H(f.RecommendedRemediation.Description)}</div>");
                    }
                    sb.AppendLine("        </div>");
                }

                sb.AppendLine("      </div>");
            }
        }

        sb.AppendLine("    </div>");

        // Provenance & Integrity
        sb.AppendLine("    <div class=\"watermark\">");
        sb.AppendLine($"      <div><strong>APIHunter Integrity Watermark:</strong> <code>{meta.ProvenanceSignature}</code> (Version: {meta.SignatureVersion})</div>");
        sb.AppendLine($"      <div>Coverage Hash: <code>{meta.ToolCoverageHash}</code> &bull; Generated: {meta.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC</div>");
        sb.AppendLine("    </div>");

        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        var fileName = $"security-scan-report-{meta.ScanJobId:N}.html";
        return new FormattedReportResult(sb.ToString(), ContentType, fileName);
    }

    private static string H(string? input) => WebUtility.HtmlEncode(input ?? string.Empty);
}
