using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Platform.Application.Scanning.Contracts;
using Platform.Domain.Enums;

namespace Platform.Application.Scanning.Reporting.Formatters;

/// <summary>
/// Projects the canonical report into strict OASIS SARIF 2.1.0 JSON format for CI/CD and GitHub Security tab integration.
/// Invariant: Only maps pre-sanitized canonical findings, never leaking raw tokens or secret authorization headers.
/// </summary>
public class SarifSecurityReportFormatter : ISecurityReportFormatter
{
    public SecurityReportFormat Format => SecurityReportFormat.Sarif;
    public string ContentType => "application/sarif+json";
    public string FileExtension => "sarif";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public FormattedReportResult FormatReport(CanonicalSecurityReport report)
    {
        // 1. Build distinct rules from findings
        var distinctFindingTypes = report.Findings
            .Select(f => f.FindingType.ToString())
            .Distinct()
            .ToList();

        var rules = new List<object>();
        foreach (var ft in distinctFindingTypes)
        {
            var sample = report.Findings.First(f => f.FindingType.ToString() == ft);
            rules.Add(new
            {
                id = ft,
                name = sample.FindingType.ToString(),
                shortDescription = new { text = sample.Title },
                fullDescription = new { text = string.IsNullOrWhiteSpace(sample.Description) ? sample.Title : sample.Description },
                defaultConfiguration = new { level = MapSeverityToSarifLevel(sample.Severity) },
                properties = new
                {
                    tags = new[] { "security", "vulnerability", "api-hunter" }
                }
            });
        }

        // 2. Build results from findings
        var results = new List<object>();
        foreach (var finding in report.Findings)
        {
            var primaryEvidence = finding.SanitizedEvidences.FirstOrDefault();
            var targetUri = !string.IsNullOrWhiteSpace(primaryEvidence?.EvidenceReference)
                ? primaryEvidence.EvidenceReference
                : report.Metadata.TargetUrl;

            results.Add(new
            {
                ruleId = finding.FindingType.ToString(),
                level = MapSeverityToSarifLevel(finding.Severity),
                message = new { text = $"{finding.Title} - {finding.Description}" },
                locations = new[]
                {
                    new
                    {
                        physicalLocation = new
                        {
                            artifactLocation = new
                            {
                                uri = targetUri
                            }
                        }
                    }
                },
                properties = new
                {
                    findingFingerprint = finding.FindingFingerprint,
                    severity = finding.Severity.ToString(),
                    riskScore = finding.RiskScore,
                    confidence = finding.Confidence.ToString(),
                    status = finding.Status.ToString(),
                    cveList = finding.CveList,
                    cweList = finding.CweList,
                    cvssScore = finding.CvssScore
                }
            });
        }

        var sarifDoc = new
        {
            schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version = "2.1.0",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "APIHunter Security Platform",
                            version = "1.0.0",
                            informationUri = "https://github.com/rajiv-kumar-1478/APIHunterSecurityPlatform",
                            rules = rules
                        }
                    },
                    results = results,
                    invocations = new[]
                    {
                        new
                        {
                            executionSuccessful = report.Metadata.JobStatus == SecurityScanJobStatus.Completed || report.Metadata.JobStatus == SecurityScanJobStatus.CompletedWithWarnings,
                            startTimeUtc = report.Metadata.StartedAtUtc?.ToString("O"),
                            endTimeUtc = report.Metadata.CompletedAtUtc?.ToString("O")
                        }
                    }
                }
            }
        };

        var json = JsonSerializer.Serialize(sarifDoc, JsonOpts);
        // Replace schema with $schema in JSON output
        json = json.Replace("\"schema\":", "\"$schema\":");

        var fileName = $"security-scan-report-{report.Metadata.ScanJobId:N}.sarif";
        return new FormattedReportResult(json, ContentType, fileName);
    }

    private static string MapSeverityToSarifLevel(RiskSeverity severity) => severity switch
    {
        RiskSeverity.Critical => "error",
        RiskSeverity.High => "error",
        RiskSeverity.Medium => "warning",
        RiskSeverity.Low => "note",
        RiskSeverity.Info => "note",
        _ => "warning"
    };
}
