using System;
using System.Collections.Generic;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Deterministic rule policy governing Semgrep SAST rule selection, rule-pack versions,
/// and external registry access.
/// </summary>
public sealed record SemgrepRulePolicy(
    IReadOnlyList<string> StandardRuleSet,
    IReadOnlyList<string> DeepRuleSet,
    bool AllowExternalRegistryRules,
    string RuleSetVersion
)
{
    public static SemgrepRulePolicy Default { get; } = new(
        StandardRuleSet: new[]
        {
            "p/r2c-security-audit",
            "p/owasp-top-ten"
        },
        DeepRuleSet: new[]
        {
            "p/r2c-security-audit",
            "p/owasp-top-ten",
            "p/csharp",
            "p/golang",
            "p/python",
            "p/javascript",
            "p/typescript",
            "p/command-injection",
            "p/sql-injection",
            "p/insecure-transport"
        },
        AllowExternalRegistryRules: true,
        RuleSetVersion: "2026.08.1"
    );
}

/// <summary>
/// Execution options for repository-level Semgrep SAST scans.
/// </summary>
public sealed record SemgrepExecutionOptions(
    SemgrepRulePolicy RulePolicy,
    IReadOnlyList<string>? TargetFiles = null,
    bool IsIncremental = false,
    int TimeoutSeconds = 300
);
