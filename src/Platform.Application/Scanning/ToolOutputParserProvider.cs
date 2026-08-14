using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Platform.Application.Scanning.Contracts;
using Platform.Application.Scanning.Parsers;

namespace Platform.Application.Scanning;

/// <summary>
/// Default implementation of IToolOutputParserProvider.
/// Maintains case-insensitive registry of tool output parsers.
/// </summary>
public class ToolOutputParserProvider : IToolOutputParserProvider
{
    private readonly Dictionary<string, IToolOutputParser> _parsers = new(StringComparer.OrdinalIgnoreCase);

    public ToolOutputParserProvider(IEnumerable<IToolOutputParser>? parsers = null)
    {
        // Register default parsers
        RegisterParser(new NucleiOutputParser());
        RegisterParser(new HttpxOutputParser());
        RegisterParser(new SubfinderOutputParser());

        // Register any custom injected parsers
        if (parsers != null)
        {
            foreach (var parser in parsers)
            {
                RegisterParser(parser);
            }
        }
    }

    public void RegisterParser(IToolOutputParser parser)
    {
        ArgumentNullException.ThrowIfNull(parser);
        _parsers[parser.ToolKey] = parser;
    }

    public IToolOutputParser? GetParser(string toolKey)
    {
        if (string.IsNullOrWhiteSpace(toolKey)) return null;
        _parsers.TryGetValue(toolKey.Trim(), out var parser);
        return parser;
    }

    public bool TryGetParser(string toolKey, [NotNullWhen(true)] out IToolOutputParser? parser)
    {
        parser = null;
        if (string.IsNullOrWhiteSpace(toolKey)) return false;
        return _parsers.TryGetValue(toolKey.Trim(), out parser);
    }
}
