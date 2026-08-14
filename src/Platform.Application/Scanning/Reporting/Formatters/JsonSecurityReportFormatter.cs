using System.Text.Json;
using System.Text.Json.Serialization;
using Platform.Application.Scanning.Contracts;

namespace Platform.Application.Scanning.Reporting.Formatters;

/// <summary>
/// Projects the canonical report into structured, machine-readable JSON format.
/// </summary>
public class JsonSecurityReportFormatter : ISecurityReportFormatter
{
    public SecurityReportFormat Format => SecurityReportFormat.Json;
    public string ContentType => "application/json";
    public string FileExtension => "json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public FormattedReportResult FormatReport(CanonicalSecurityReport report)
    {
        var json = JsonSerializer.Serialize(report, JsonOpts);
        var fileName = $"security-scan-report-{report.Metadata.ScanJobId:N}.json";
        return new FormattedReportResult(json, ContentType, fileName);
    }
}
