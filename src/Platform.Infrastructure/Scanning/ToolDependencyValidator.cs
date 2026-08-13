using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Application.Scanning;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Scanning;

public class ToolDependencyValidator : IToolDependencyValidator
{
    private readonly IPlatformDbContext _dbContext;
    private readonly ILogger<ToolDependencyValidator> _logger;

    public ToolDependencyValidator(IPlatformDbContext dbContext, ILogger<ToolDependencyValidator> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    public async Task ValidateDependencyGraphAsync(string rootToolKey, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rootToolKey))
        {
            throw new ArgumentException("Root tool key cannot be empty.", nameof(rootToolKey));
        }

        var normalizedRoot = rootToolKey.Trim().ToLowerInvariant();
        var allTools = await _dbContext.SecurityScanTools.AsNoTracking().ToDictionaryAsync(t => t.ToolKey.ToLowerInvariant(), ct);
        var allDependencies = await _dbContext.ToolDependencies.AsNoTracking().ToListAsync(ct);

        if (!allTools.TryGetValue(normalizedRoot, out var rootTool))
        {
            throw new InvalidOperationException($"Dependency Validation Error: Root tool '{rootToolKey}' is not registered in the tool manifest.");
        }

        // Build adjacency list for dependency DAG
        var graph = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var dep in allDependencies)
        {
            var parent = dep.ParentToolKey.Trim().ToLowerInvariant();
            var child = dep.DependencyToolKey.Trim().ToLowerInvariant();

            // Reject self-dependency check
            if (string.Equals(parent, child, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Security Violation: Tool '{parent}' specifies a self-dependency on itself.");
            }

            if (!graph.ContainsKey(parent))
            {
                graph[parent] = new List<string>();
            }

            graph[parent].Add(child);

            // Verify child dependency is registered and healthy
            if (!allTools.TryGetValue(child, out var childTool))
            {
                throw new InvalidOperationException($"Dependency Validation Error: Tool '{parent}' requires dependency '{child}', but '{child}' is not registered in the database.");
            }

            if (!childTool.Enabled || childTool.HealthStatus != ToolHealthStatus.Healthy)
            {
                throw new InvalidOperationException($"Dependency Validation Error: Dependency '{child}' for tool '{parent}' is disabled or unhealthy ({childTool.HealthStatus}).");
            }

            // Verify version constraint if specified
            if (!string.IsNullOrWhiteSpace(dep.RequiredVersion) &&
                !string.Equals(childTool.Version, dep.RequiredVersion, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Dependency Validation Error: Tool '{parent}' requires '{child}' v{dep.RequiredVersion}, but found v{childTool.Version}.");
            }
        }

        // Detect cycles using DFS (Depth-First Search) with recursion stack tracking
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var recursionStack = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void DfsCycleCheck(string currentTool)
        {
            visited.Add(currentTool);
            recursionStack.Add(currentTool);

            if (graph.TryGetValue(currentTool, out var neighbors))
            {
                foreach (var neighbor in neighbors)
                {
                    if (recursionStack.Contains(neighbor))
                    {
                        _logger.LogError("Circular dependency cycle detected: {Current} -> {Neighbor}", currentTool, neighbor);
                        throw new InvalidOperationException($"Dependency Cycle Detected: Circular dependency path found involving '{currentTool}' and '{neighbor}'.");
                    }

                    if (!visited.Contains(neighbor))
                    {
                        DfsCycleCheck(neighbor);
                    }
                }
            }

            recursionStack.Remove(currentTool);
        }

        DfsCycleCheck(normalizedRoot);
        _logger.LogInformation("Dependency graph validation succeeded for root tool '{RootTool}'.", normalizedRoot);
    }
}
