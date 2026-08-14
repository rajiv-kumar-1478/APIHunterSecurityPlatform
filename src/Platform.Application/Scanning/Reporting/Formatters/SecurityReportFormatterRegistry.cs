using System;
using System.Collections.Generic;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Reporting.Formatters;

/// <summary>
/// Registry resolving report formatters by format key or enum value.
/// Strict invariant: Unknown formats throw ArgumentException (never silently fallback).
/// </summary>
public class SecurityReportFormatterRegistry
{
    private readonly Dictionary<string, ISecurityReportFormatter> _formatters = new(StringComparer.OrdinalIgnoreCase);

    public SecurityReportFormatterRegistry(IEnumerable<ISecurityReportFormatter>? customFormatters = null)
    {
        // Register default formatters
        Register(new JsonSecurityReportFormatter());
        Register(new SarifSecurityReportFormatter());
        Register(new MarkdownSecurityReportFormatter());
        Register(new HtmlSecurityReportFormatter());

        if (customFormatters != null)
        {
            foreach (var f in customFormatters)
            {
                Register(f);
            }
        }
    }

    public void Register(ISecurityReportFormatter formatter)
    {
        if (formatter == null) throw new ArgumentNullException(nameof(formatter));

        _formatters[formatter.Format.ToString().ToLowerInvariant()] = formatter;
        _formatters[formatter.FileExtension.ToLowerInvariant()] = formatter;
    }

    public ISecurityReportFormatter GetFormatter(string formatKey)
    {
        if (string.IsNullOrWhiteSpace(formatKey))
        {
            throw new ArgumentException("Report format must be specified. Supported formats: json, sarif, markdown, html.", nameof(formatKey));
        }

        var normalized = formatKey.Trim().ToLowerInvariant();
        if (normalized == "md") normalized = "markdown";

        if (_formatters.TryGetValue(normalized, out var formatter))
        {
            return formatter;
        }

        throw new ArgumentException($"Unsupported report format '{formatKey}'. Supported formats: json, sarif, markdown, html.", nameof(formatKey));
    }

    public ISecurityReportFormatter GetFormatter(SecurityReportFormat format)
    {
        return GetFormatter(format.ToString());
    }

    /// <summary>
    /// Formats the canonical report using the specified format, enforcing hard resource limits on final output size.
    /// Invariant: Outputs exceeding MaxReportOutputBytes fail closed.
    /// </summary>
    public FormattedReportResult FormatReport(string formatKey, CanonicalSecurityReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var formatter = GetFormatter(formatKey);
        var result = formatter.FormatReport(report);

        var outputByteCount = System.Text.Encoding.UTF8.GetByteCount(result.Content);
        if (outputByteCount > ReportResourceBounds.MaxReportOutputBytes)
        {
            throw new InvalidOperationException(
                $"Formatted report output size ({outputByteCount} bytes) exceeds maximum ceiling of {ReportResourceBounds.MaxReportOutputBytes} bytes.");
        }

        return result;
    }

    public FormattedReportResult FormatReport(SecurityReportFormat format, CanonicalSecurityReport report)
        => FormatReport(format.ToString(), report);
}
