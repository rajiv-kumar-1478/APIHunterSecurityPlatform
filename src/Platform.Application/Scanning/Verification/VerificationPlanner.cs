using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Application.Scanning.Verification.Contracts;

namespace Platform.Application.Scanning.Verification;

/// <summary>
/// Authoritative planner generating prioritized BugHunter active verification plans
/// from the Attack Surface Graph and deployment diffs.
/// </summary>
public sealed class VerificationPlanner : IVerificationPlanner
{
    private readonly ILogger<VerificationPlanner> _logger;

    public VerificationPlanner(ILogger<VerificationPlanner> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public BugHunterExecutionPlan GeneratePlan(
        Guid scanJobId,
        ScanTriggerSource triggerSource,
        JsAttackSurfaceGraph currentGraph,
        JsAttackSurfaceDiff? surfaceDiff = null,
        IReadOnlyList<string>? internalHosts = null)
    {
        currentGraph ??= new JsAttackSurfaceGraph(scanJobId, Array.Empty<DiscoveredApiEndpoint>(), new Dictionary<string, IReadOnlyList<Guid>>(), 0, 0, 0, 0, DateTime.UtcNow);
        internalHosts ??= Array.Empty<string>();

        var plannedItems = new List<PlannedEndpointVerification>();
        bool isIncrementalOnly = triggerSource == ScanTriggerSource.DeploymentWebhook && surfaceDiff != null;

        if (isIncrementalOnly && surfaceDiff != null)
        {
            // 1. Incremental deployment scan: Plan ONLY newly discovered and changed endpoints
            foreach (var newEp in surfaceDiff.NewEndpoints)
            {
                var testCategories = DetermineTestCategories(newEp);
                plannedItems.Add(new PlannedEndpointVerification(
                    PlanId: Guid.NewGuid(),
                    Endpoint: newEp,
                    Priority: VerificationPriority.Critical,
                    RecommendedTestCategories: testCategories,
                    Rationale: "Newly introduced API endpoint in recent deployment"
                ));
            }

            foreach (var changedEp in surfaceDiff.ChangedEndpoints)
            {
                var testCategories = DetermineTestCategories(changedEp);
                plannedItems.Add(new PlannedEndpointVerification(
                    PlanId: Guid.NewGuid(),
                    Endpoint: changedEp,
                    Priority: VerificationPriority.High,
                    RecommendedTestCategories: testCategories,
                    Rationale: "Modified API endpoint signature or parameters in recent deployment"
                ));
            }
        }
        else
        {
            // 2. Cold-start or scheduled full scan: Plan all discovered endpoints
            foreach (var ep in currentGraph.Endpoints)
            {
                var priority = CalculateFullScanPriority(ep);
                var testCategories = DetermineTestCategories(ep);

                plannedItems.Add(new PlannedEndpointVerification(
                    PlanId: Guid.NewGuid(),
                    Endpoint: ep,
                    Priority: priority,
                    RecommendedTestCategories: testCategories,
                    Rationale: priority == VerificationPriority.High
                        ? "Endpoint contains sensitive path or privilege parameters"
                        : "Baseline attack surface endpoint"
                ));
            }
        }

        // Sort by priority (Critical first, then High, Medium, Low)
        var sortedItems = plannedItems.OrderBy(p => (int)p.Priority).ToList();

        return new BugHunterExecutionPlan(
            ScanJobId: scanJobId,
            TriggerSource: triggerSource,
            PrioritizedEndpoints: sortedItems.AsReadOnly(),
            DiscoveredInternalHosts: internalHosts,
            IsIncrementalOnly: isIncrementalOnly,
            TotalEndpointsPlanned: sortedItems.Count,
            PlannedAtUtc: DateTime.UtcNow
        );
    }

    private static VerificationPriority CalculateFullScanPriority(DiscoveredApiEndpoint ep)
    {
        // Path parameters (e.g. /users/{id}) are prime targets for BOLA/IDOR
        if (ep.Parameters.Any(p => p.Location == ParameterLocation.Path))
        {
            return VerificationPriority.High;
        }

        // Sensitive parameter names (role, admin, token, tenant)
        if (ep.Parameters.Any(p => IsSensitiveParameterName(p.Name)))
        {
            return VerificationPriority.High;
        }

        if (ep.Protocol == ApiEndpointProtocol.GraphQL)
        {
            return VerificationPriority.High;
        }

        return VerificationPriority.Medium;
    }

    private static IReadOnlyList<string> DetermineTestCategories(DiscoveredApiEndpoint ep)
    {
        var categories = new List<string>();

        if (ep.Protocol == ApiEndpointProtocol.GraphQL)
        {
            categories.Add("GraphQLIntrospection");
            categories.Add("GraphQLQueryBatching");
            categories.Add("GraphQLBolaVerification");
            return categories.AsReadOnly();
        }

        if (ep.Protocol == ApiEndpointProtocol.WebSocket)
        {
            categories.Add("WebSocketAuthValidation");
            return categories.AsReadOnly();
        }

        // REST / HTTP
        categories.Add("ContractFuzzing");

        if (ep.Parameters.Any(p => p.Location == ParameterLocation.Path))
        {
            categories.Add("BolaBoundaryVerification");
        }

        if (ep.Parameters.Any(p => p.Location is ParameterLocation.Query or ParameterLocation.Body))
        {
            categories.Add("ParameterTampering");
        }

        if (ep.HttpMethod is "POST" or "PUT" or "PATCH")
        {
            categories.Add("MassAssignmentVerification");
        }

        return categories.AsReadOnly();
    }

    private static bool IsSensitiveParameterName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var lower = name.ToLowerInvariant();
        return lower.Contains("id") ||
               lower.Contains("user") ||
               lower.Contains("role") ||
               lower.Contains("admin") ||
               lower.Contains("tenant") ||
               lower.Contains("account") ||
               lower.Contains("token") ||
               lower.Contains("auth") ||
               lower.Contains("privilege");
    }
}
