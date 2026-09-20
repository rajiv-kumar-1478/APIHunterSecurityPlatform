using System.Text.RegularExpressions;
using Platform.Application.Operations;

namespace Platform.Infrastructure.Operations;

public class OperationalPromptSanitizer : IOperationalPromptSanitizer
{
    private static readonly (Regex Pattern, string Replacement)[] SanitizationRules =
    [
        // Bearer / Basic authorization headers
        (new Regex(@"(?i)bearer\s+[a-zA-Z0-9_\-\.]{10,}", RegexOptions.Compiled), "Bearer [REDACTED]"),
        (new Regex(@"(?i)basic\s+[a-zA-Z0-9+/=]{10,}", RegexOptions.Compiled), "Basic [REDACTED]"),
        (new Regex(@"(?i)authorization:\s*[^\r\n]+", RegexOptions.Compiled), "Authorization: [REDACTED]"),

        // Connection strings and passwords
        (new Regex(@"(?i)(password|pwd|user\s*id|uid)\s*=\s*[^;\r\n]+", RegexOptions.Compiled), "$1=[REDACTED]"),

        // Provider specific token patterns
        (new Regex(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled), "AKIA[REDACTED]"),
        (new Regex(@"gh[pousr]_[0-9a-zA-Z]{36}", RegexOptions.Compiled), "ghp_[REDACTED]"),
        (new Regex(@"xox[baprs]-[0-9a-zA-Z\-]{20,}", RegexOptions.Compiled), "xox-[REDACTED]"),
        (new Regex(@"sk-[a-zA-Z0-9_\-]{20,}", RegexOptions.Compiled), "sk-[REDACTED]"),
        (new Regex(@"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", RegexOptions.Compiled), "SG.[REDACTED]"),
        (new Regex(@"key-[0-9a-zA-Z]{32}", RegexOptions.Compiled), "key-[REDACTED]"),

        // Generic secret/token/apiKey key-value assignments
        (new Regex(@"(?i)(api[_-]?key|secret|token|private[_-]?key)\s*[:=]\s*['""][^'""]{8,}['""]", RegexOptions.Compiled), "$1: \"[REDACTED]\""),
        (new Regex(@"(?i)(api[_-]?key|secret|token|private[_-]?key)\s*[:=]\s*[^,\s;\r\n]{8,}", RegexOptions.Compiled), "$1=[REDACTED]")
    ];

    public string Sanitize(string? rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return string.Empty;
        }

        var result = rawText;
        foreach (var (pattern, replacement) in SanitizationRules)
        {
            result = pattern.Replace(result, replacement);
        }

        return result;
    }
}
