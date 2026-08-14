using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Reporting.Formatters;

/// <summary>
/// Pure projection contract converting an authoritative CanonicalSecurityReport into a specific export format.
/// Invariant: Formatters must never query databases or alter findings.
/// </summary>
public interface ISecurityReportFormatter
{
    SecurityReportFormat Format { get; }
    string ContentType { get; }
    string FileExtension { get; }

    FormattedReportResult FormatReport(CanonicalSecurityReport report);
}
