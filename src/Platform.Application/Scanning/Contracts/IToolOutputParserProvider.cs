using System.Diagnostics.CodeAnalysis;

namespace Platform.Application.Scanning.Contracts;

/// <summary>
/// Provider registry for resolving tool-specific output parsers.
/// </summary>
public interface IToolOutputParserProvider
{
    /// <summary>
    /// Retrieves a registered parser for the specified tool key, or null if unsupported.
    /// </summary>
    IToolOutputParser? GetParser(string toolKey);

    /// <summary>
    /// Attempts to retrieve a registered parser for the specified tool key.
    /// </summary>
    bool TryGetParser(string toolKey, [NotNullWhen(true)] out IToolOutputParser? parser);
}
