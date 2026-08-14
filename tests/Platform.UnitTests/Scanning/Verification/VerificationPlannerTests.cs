using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using Platform.Application.Scanning.JavaScript.Contracts;
using Platform.Application.Scanning.Verification;
using Platform.Application.Scanning.Verification.Contracts;
using Platform.Domain.Enums;
using Xunit;

namespace Platform.UnitTests.Scanning.Verification;

public class VerificationPlannerTests
{
    private readonly VerificationPlanner _planner;

    public VerificationPlannerTests()
    {
        _planner = new VerificationPlanner(NullLogger<VerificationPlanner>.Instance);
    }

    [Fact]
    public void GeneratePlan_DeploymentWebhookWithDiff_PlansOnlyNewAndChangedEndpoints()
    {
        var scanJobId = Guid.NewGuid();

        var epNew = new DiscoveredApiEndpoint(Guid.NewGuid(), "https://app.example.com/app.js", "POST", "/api/admin/users", null, ApiEndpointProtocol.HttpRest, new[] { new DiscoveredParameter("userId", ParameterLocation.Path) }, new Dictionary<string, string>(), null, null, null, "fetch(...)", 10, 5, ResolutionQuality.ASTLiteral, FindingConfidence.High);
        var epChanged = new DiscoveredApiEndpoint(Guid.NewGuid(), "https://app.example.com/app.js", "PUT", "/api/users/{id}/profile", null, ApiEndpointProtocol.HttpRest, new[] { new DiscoveredParameter("id", ParameterLocation.Path), new DiscoveredParameter("role", ParameterLocation.Body) }, new Dictionary<string, string>(), null, null, null, "fetch(...)", 20, 5, ResolutionQuality.ASTConstantFolded, FindingConfidence.High);
        var epUnchanged = new DiscoveredApiEndpoint(Guid.NewGuid(), "https://app.example.com/app.js", "GET", "/api/health", null, ApiEndpointProtocol.HttpRest, Array.Empty<DiscoveredParameter>(), new Dictionary<string, string>(), null, null, null, "fetch(...)", 30, 5, ResolutionQuality.ASTLiteral, FindingConfidence.High);

        var currentGraph = new JsAttackSurfaceGraph(scanJobId, new[] { epNew, epChanged, epUnchanged }, new Dictionary<string, IReadOnlyList<Guid>>(), 3, 3, 0, 0, DateTime.UtcNow);

        var diff = new JsAttackSurfaceDiff(
            scanJobId,
            Guid.NewGuid(),
            NewEndpoints: new[] { epNew },
            ChangedEndpoints: new[] { epChanged },
            UnchangedEndpoints: new[] { epUnchanged },
            RemovedEndpoints: Array.Empty<DiscoveredApiEndpoint>(),
            GeneratedAtUtc: DateTime.UtcNow
        );

        var plan = _planner.GeneratePlan(scanJobId, ScanTriggerSource.DeploymentWebhook, currentGraph, diff);

        Assert.True(plan.IsIncrementalOnly);
        Assert.Equal(2, plan.TotalEndpointsPlanned);

        // First item is Critical (New endpoint)
        Assert.Equal(VerificationPriority.Critical, plan.PrioritizedEndpoints[0].Priority);
        Assert.Equal("/api/admin/users", plan.PrioritizedEndpoints[0].Endpoint.RoutePath);
        Assert.Contains("BolaBoundaryVerification", plan.PrioritizedEndpoints[0].RecommendedTestCategories);

        // Second item is High (Changed endpoint)
        Assert.Equal(VerificationPriority.High, plan.PrioritizedEndpoints[1].Priority);
        Assert.Equal("/api/users/{id}/profile", plan.PrioritizedEndpoints[1].Endpoint.RoutePath);
    }

    [Fact]
    public void GeneratePlan_ColdStartDeployment_FallsBackToFullAttackSurface()
    {
        var scanJobId = Guid.NewGuid();

        var ep1 = new DiscoveredApiEndpoint(Guid.NewGuid(), "https://app.example.com/app.js", "POST", "/api/auth/login", null, ApiEndpointProtocol.HttpRest, new[] { new DiscoveredParameter("username", ParameterLocation.Body) }, new Dictionary<string, string>(), null, null, null, "fetch(...)", 10, 5, ResolutionQuality.ASTLiteral, FindingConfidence.High);
        var ep2 = new DiscoveredApiEndpoint(Guid.NewGuid(), "https://app.example.com/app.js", "GET", "/api/users/{id}", null, ApiEndpointProtocol.HttpRest, new[] { new DiscoveredParameter("id", ParameterLocation.Path) }, new Dictionary<string, string>(), null, null, null, "fetch(...)", 20, 5, ResolutionQuality.ASTTemplateResolvable, FindingConfidence.High);

        var currentGraph = new JsAttackSurfaceGraph(scanJobId, new[] { ep1, ep2 }, new Dictionary<string, IReadOnlyList<Guid>>(), 2, 2, 0, 0, DateTime.UtcNow);

        // surfaceDiff is null (Cold start / no baseline)
        var plan = _planner.GeneratePlan(scanJobId, ScanTriggerSource.DeploymentWebhook, currentGraph, surfaceDiff: null);

        Assert.False(plan.IsIncrementalOnly);
        Assert.Equal(2, plan.TotalEndpointsPlanned);

        // Endpoint with Path param (BOLA candidate) receives High priority
        var bolaItem = plan.PrioritizedEndpoints.First(p => p.Endpoint.RoutePath == "/api/users/{id}");
        Assert.Equal(VerificationPriority.High, bolaItem.Priority);
        Assert.Contains("BolaBoundaryVerification", bolaItem.RecommendedTestCategories);
    }
}
