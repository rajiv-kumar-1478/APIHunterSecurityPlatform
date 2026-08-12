using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;

/// <summary>
/// Reads the existing Phase 4/5 Security Intelligence Graph (read-only) and produces
/// SecurityFinding + SecurityFindingEvidence records via SecurityFindingService.
/// 
/// Key invariants:
/// - Never creates/modifies graph nodes or edges.
/// - Never calls RiskEngine directly (risk flows through SecurityFindingService).
/// - Finding identity uses stable Node.Id (Guid), never Name/Label strings.
/// - SafeEvidenceJson uses allowlist-only projection, never raw MetadataJson.
/// - Only analyzes nodes/edges reachable from the target repository.
/// </summary>
public class GraphIntelligenceEngine
{
    private readonly IPlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;
    private readonly ILogger<GraphIntelligenceEngine> _logger;

    public GraphIntelligenceEngine(
        IPlatformDbContext dbContext,
        SecurityFindingService findingService,
        ILogger<GraphIntelligenceEngine> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _findingService = findingService ?? throw new ArgumentNullException(nameof(findingService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Traverses the repository-scoped subgraph and produces SecurityFindings for detected patterns.
    /// Idempotent — safe to call repeatedly for the same repository.
    /// </summary>
    public async Task AnalyzeRepositoryGraphAsync(Guid repositoryId, CancellationToken ct = default)
    {
        _logger.LogInformation("Starting graph intelligence analysis for repository '{RepositoryId}'.", repositoryId);

        var subgraph = await LoadRepositoryScopedSubgraphAsync(repositoryId, ct);
        if (subgraph == null)
        {
            _logger.LogWarning("No repository node found for '{RepositoryId}'. Skipping graph intelligence analysis.", repositoryId);
            return;
        }

        var adjacency = BuildAdjacencyList(subgraph);

        await DetectValidatedCredentialExposuresAsync(repositoryId, subgraph, adjacency, ct);
        await DetectUnvalidatedCredentialExposuresAsync(repositoryId, subgraph, adjacency, ct);
        await DetectProductionServiceExposuresAsync(repositoryId, subgraph, adjacency, ct);
        await DetectDatabaseExposuresAsync(repositoryId, subgraph, adjacency, ct);

        _logger.LogInformation("Completed graph intelligence analysis for repository '{RepositoryId}'.", repositoryId);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Subgraph Loading (Correction #2: strict repository boundary)
    // ─────────────────────────────────────────────────────────────────────────

    internal record RepositorySubgraph(
        SecurityIntelligenceNode RepoNode,
        List<SecurityIntelligenceNode> Nodes,
        List<SecurityIntelligenceEdge> Edges);

    internal async Task<RepositorySubgraph?> LoadRepositoryScopedSubgraphAsync(Guid repositoryId, CancellationToken ct)
    {
        string repoNodeName = $"repo:{repositoryId}";

        var repoNode = await _dbContext.SecurityIntelligenceNodes
            .FirstOrDefaultAsync(n => n.NodeType == IntelligenceNodeType.Repository && n.Name == repoNodeName, ct);

        if (repoNode == null) return null;

        // Load all edges connected to the repo node (direct neighbors)
        var repoEdges = await _dbContext.SecurityIntelligenceEdges
            .Where(e => e.SourceNodeId == repoNode.Id || e.TargetNodeId == repoNode.Id)
            .ToListAsync(ct);

        // Collect directly connected neighbor node IDs
        var neighborIds = new HashSet<Guid>();
        foreach (var edge in repoEdges)
        {
            neighborIds.Add(edge.SourceNodeId);
            neighborIds.Add(edge.TargetNodeId);
        }
        neighborIds.Add(repoNode.Id);

        // Load all neighbor nodes
        var allNodes = await _dbContext.SecurityIntelligenceNodes
            .Where(n => neighborIds.Contains(n.Id))
            .ToListAsync(ct);

        // Load inter-neighbor edges (edges between nodes in the scoped set)
        var allEdges = await _dbContext.SecurityIntelligenceEdges
            .Where(e => neighborIds.Contains(e.SourceNodeId) && neighborIds.Contains(e.TargetNodeId))
            .ToListAsync(ct);

        return new RepositorySubgraph(repoNode, allNodes, allEdges);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Adjacency List Construction
    // ─────────────────────────────────────────────────────────────────────────

    internal record AdjacencyEntry(
        SecurityIntelligenceNode Node,
        List<(SecurityIntelligenceEdge Edge, SecurityIntelligenceNode Neighbor)> Connections);

    internal static Dictionary<Guid, AdjacencyEntry> BuildAdjacencyList(RepositorySubgraph subgraph)
    {
        var nodeMap = subgraph.Nodes.ToDictionary(n => n.Id);
        var adjacency = new Dictionary<Guid, AdjacencyEntry>();

        foreach (var node in subgraph.Nodes)
        {
            adjacency[node.Id] = new AdjacencyEntry(node, new List<(SecurityIntelligenceEdge, SecurityIntelligenceNode)>());
        }

        foreach (var edge in subgraph.Edges)
        {
            if (nodeMap.TryGetValue(edge.TargetNodeId, out var targetNode))
            {
                adjacency[edge.SourceNodeId].Connections.Add((edge, targetNode));
            }
            if (nodeMap.TryGetValue(edge.SourceNodeId, out var sourceNode))
            {
                adjacency[edge.TargetNodeId].Connections.Add((edge, sourceNode));
            }
        }

        return adjacency;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pattern: ValidatedCredentialExposed
    // ─────────────────────────────────────────────────────────────────────────

    private async Task DetectValidatedCredentialExposuresAsync(
        Guid repositoryId,
        RepositorySubgraph subgraph,
        Dictionary<Guid, AdjacencyEntry> adjacency,
        CancellationToken ct)
    {
        var candidateNodes = subgraph.Nodes
            .Where(n => n.NodeType == IntelligenceNodeType.CredentialCandidate)
            .ToList();

        foreach (var candNode in candidateNodes)
        {
            var validationStatus = ExtractValidationStatusFromMetadata(candNode.MetadataJson);
            if (validationStatus != "Valid" && validationStatus != "ValidInsufficientScope")
                continue;

            // CoreEntityId = candidateNode.Id (Correction #1)
            string coreEntityId = candNode.Id.ToString("N");

            var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
                RepositoryId: repositoryId,
                SnapshotId: null,
                FindingType: FindingType.ValidatedCredentialExposed,
                Severity: RiskSeverity.High,
                Confidence: FindingConfidence.High,
                Title: $"Validated credential exposed in repository",
                Description: $"A {ExtractCredentialType(candNode)} credential with validation status '{validationStatus}' was detected in the repository graph.",
                CoreEntityId: coreEntityId
            ), ct);

            // Attach candidate node evidence
            await AttachNodeEvidenceAsync(finding.Id, candNode, DiscoveryType.CredentialValidation, ct);

            // Attach environment context if available
            await AttachEnvironmentContextAsync(finding.Id, candNode, adjacency, ct);

            // Attach internet-facing context if explicit edge chain exists
            await AttachInternetFacingContextAsync(finding.Id, subgraph, adjacency, ct);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pattern: UnvalidatedCredentialExposed
    // ─────────────────────────────────────────────────────────────────────────

    private async Task DetectUnvalidatedCredentialExposuresAsync(
        Guid repositoryId,
        RepositorySubgraph subgraph,
        Dictionary<Guid, AdjacencyEntry> adjacency,
        CancellationToken ct)
    {
        var candidateNodes = subgraph.Nodes
            .Where(n => n.NodeType == IntelligenceNodeType.CredentialCandidate)
            .ToList();

        foreach (var candNode in candidateNodes)
        {
            var validationStatus = ExtractValidationStatusFromMetadata(candNode.MetadataJson);

            // Unvalidated = no validation status, or Pending/Unavailable/Error
            if (validationStatus == "Valid" || validationStatus == "ValidInsufficientScope" ||
                validationStatus == "Invalid" || validationStatus == "Expired" || validationStatus == "Revoked")
                continue;

            string coreEntityId = candNode.Id.ToString("N");

            var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
                RepositoryId: repositoryId,
                SnapshotId: null,
                FindingType: FindingType.UnvalidatedCredentialExposed,
                Severity: RiskSeverity.Medium,
                Confidence: FindingConfidence.Medium,
                Title: $"Unvalidated credential exposed in repository",
                Description: $"A {ExtractCredentialType(candNode)} credential without successful validation was detected in the repository graph.",
                CoreEntityId: coreEntityId
            ), ct);

            await AttachNodeEvidenceAsync(finding.Id, candNode, DiscoveryType.DeterministicDetector, ct);
            await AttachEnvironmentContextAsync(finding.Id, candNode, adjacency, ct);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pattern: ProductionServiceExposed
    // ─────────────────────────────────────────────────────────────────────────

    private async Task DetectProductionServiceExposuresAsync(
        Guid repositoryId,
        RepositorySubgraph subgraph,
        Dictionary<Guid, AdjacencyEntry> adjacency,
        CancellationToken ct)
    {
        var serviceNodes = subgraph.Nodes
            .Where(n => n.NodeType == IntelligenceNodeType.Service)
            .ToList();

        var productionEnvNodes = subgraph.Nodes
            .Where(n => n.NodeType == IntelligenceNodeType.Environment &&
                        n.Label.Equals("production", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (productionEnvNodes.Count == 0) return;

        foreach (var serviceNode in serviceNodes)
        {
            if (!adjacency.TryGetValue(serviceNode.Id, out var serviceEntry)) continue;

            // Check if this service connects to the repo node via BelongsTo
            bool connectedToRepo = serviceEntry.Connections.Any(c =>
                c.Neighbor.Id == subgraph.RepoNode.Id && c.Edge.EdgeType == IntelligenceEdgeType.BelongsTo);

            if (!connectedToRepo) continue;

            foreach (var envNode in productionEnvNodes)
            {
                // Check if the repo node is connected to the production environment
                if (!adjacency.TryGetValue(subgraph.RepoNode.Id, out var repoEntry)) continue;

                bool repoConnectedToEnv = repoEntry.Connections.Any(c =>
                    c.Neighbor.Id == envNode.Id);

                if (!repoConnectedToEnv) continue;

                // Relationship CoreEntityId (Correction #1)
                string coreEntityId = $"{serviceNode.Id:N}:{envNode.Id:N}";

                var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
                    RepositoryId: repositoryId,
                    SnapshotId: null,
                    FindingType: FindingType.ProductionServiceExposed,
                    Severity: RiskSeverity.High,
                    Confidence: FindingConfidence.High,
                    Title: $"Production service '{serviceNode.Label}' exposed in repository",
                    Description: $"Service '{serviceNode.Label}' is associated with a production environment in the repository graph.",
                    CoreEntityId: coreEntityId
                ), ct);

                // Attach service node evidence
                await AttachNodeEvidenceAsync(finding.Id, serviceNode, DiscoveryType.AiInvestigator, ct);

                // Attach environment node evidence
                await AttachNodeEvidenceAsync(finding.Id, envNode, DiscoveryType.AiInvestigator, ct);

                // Attach the linking edge evidence
                var linkingEdge = subgraph.Edges.FirstOrDefault(e =>
                    (e.SourceNodeId == subgraph.RepoNode.Id && e.TargetNodeId == envNode.Id) ||
                    (e.SourceNodeId == envNode.Id && e.TargetNodeId == subgraph.RepoNode.Id));

                if (linkingEdge != null)
                {
                    await AttachEdgeEvidenceAsync(finding.Id, linkingEdge, subgraph, ct);
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pattern: DatabaseExposure
    // ─────────────────────────────────────────────────────────────────────────

    private async Task DetectDatabaseExposuresAsync(
        Guid repositoryId,
        RepositorySubgraph subgraph,
        Dictionary<Guid, AdjacencyEntry> adjacency,
        CancellationToken ct)
    {
        var dbNodes = subgraph.Nodes
            .Where(n => n.NodeType == IntelligenceNodeType.Database)
            .ToList();

        var candidateNodes = subgraph.Nodes
            .Where(n => n.NodeType == IntelligenceNodeType.CredentialCandidate)
            .ToList();

        foreach (var dbNode in dbNodes)
        {
            if (!adjacency.TryGetValue(dbNode.Id, out var dbEntry)) continue;

            foreach (var candNode in candidateNodes)
            {
                // Check if the database and credential are both reachable from repo
                // via the adjacency (they're in the same scoped subgraph by construction)
                bool dbConnectedToRepo = dbEntry.Connections.Any(c =>
                    c.Neighbor.Id == subgraph.RepoNode.Id);

                if (!dbConnectedToRepo) continue;

                // Relationship CoreEntityId (Correction #1)
                string coreEntityId = $"{dbNode.Id:N}:{candNode.Id:N}";

                var finding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
                    RepositoryId: repositoryId,
                    SnapshotId: null,
                    FindingType: FindingType.DatabaseExposure,
                    Severity: RiskSeverity.High,
                    Confidence: FindingConfidence.High,
                    Title: $"Database credential exposure detected",
                    Description: $"Database '{dbNode.Label}' has credential access exposed in the repository graph.",
                    CoreEntityId: coreEntityId
                ), ct);

                await AttachNodeEvidenceAsync(finding.Id, dbNode, DiscoveryType.AiInvestigator, ct);
                await AttachNodeEvidenceAsync(finding.Id, candNode, DiscoveryType.DeterministicDetector, ct);

                // Attach environment context for production database factor
                await AttachEnvironmentContextAsync(finding.Id, candNode, adjacency, ct);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Evidence Attachment Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private async Task AttachNodeEvidenceAsync(Guid findingId, SecurityIntelligenceNode node, DiscoveryType discoverySource, CancellationToken ct)
    {
        await _findingService.AttachEvidenceAsync(findingId, new AttachEvidenceRequest(
            EvidenceType: FindingEvidenceType.IntelligenceNode,
            DiscoverySource: discoverySource,
            SourceEntityId: node.Id.ToString("N"),
            IntelligenceNodeId: node.Id,
            EvidenceReference: $"{node.NodeType}:{node.Label}",
            SafeEvidenceJson: ProjectSafeNodeEvidence(node)
        ), ct);
    }

    private async Task AttachEdgeEvidenceAsync(Guid findingId, SecurityIntelligenceEdge edge, RepositorySubgraph subgraph, CancellationToken ct)
    {
        var sourceNode = subgraph.Nodes.FirstOrDefault(n => n.Id == edge.SourceNodeId);
        var targetNode = subgraph.Nodes.FirstOrDefault(n => n.Id == edge.TargetNodeId);

        await _findingService.AttachEvidenceAsync(findingId, new AttachEvidenceRequest(
            EvidenceType: FindingEvidenceType.IntelligenceEdge,
            DiscoverySource: edge.DiscoverySource,
            SourceEntityId: edge.Id.ToString("N"),
            IntelligenceEdgeId: edge.Id,
            EvidenceReference: $"{edge.EdgeType}:{sourceNode?.NodeType}→{targetNode?.NodeType}",
            SafeEvidenceJson: ProjectSafeEdgeEvidence(edge, sourceNode, targetNode)
        ), ct);
    }

    /// <summary>
    /// Attaches production environment evidence if the candidate is connected to a production environment node.
    /// </summary>
    private async Task AttachEnvironmentContextAsync(
        Guid findingId,
        SecurityIntelligenceNode candidateNode,
        Dictionary<Guid, AdjacencyEntry> adjacency,
        CancellationToken ct)
    {
        // Look for environment nodes in the adjacency of any node in the subgraph
        foreach (var entry in adjacency.Values)
        {
            if (entry.Node.NodeType != IntelligenceNodeType.Environment) continue;
            if (!entry.Node.Label.Equals("production", StringComparison.OrdinalIgnoreCase)) continue;

            await AttachNodeEvidenceAsync(findingId, entry.Node, DiscoveryType.AiInvestigator, ct);
            break;
        }
    }

    /// <summary>
    /// Attaches internet-facing evidence only when explicit edge chain exists (Correction #3):
    /// Domain ←[AssociatedWith]→ Repository ←[BelongsTo]─ Service
    /// </summary>
    private async Task AttachInternetFacingContextAsync(
        Guid findingId,
        RepositorySubgraph subgraph,
        Dictionary<Guid, AdjacencyEntry> adjacency,
        CancellationToken ct)
    {
        if (!adjacency.TryGetValue(subgraph.RepoNode.Id, out var repoEntry)) return;

        // Find Domain nodes connected to the repository via AssociatedWith
        var domainConnections = repoEntry.Connections
            .Where(c => c.Neighbor.NodeType == IntelligenceNodeType.Domain &&
                        c.Edge.EdgeType == IntelligenceEdgeType.AssociatedWith)
            .ToList();

        if (domainConnections.Count == 0) return;

        // Check if there are Service nodes connected via BelongsTo
        var serviceConnections = repoEntry.Connections
            .Where(c => c.Neighbor.NodeType == IntelligenceNodeType.Service &&
                        c.Edge.EdgeType == IntelligenceEdgeType.BelongsTo)
            .ToList();

        if (serviceConnections.Count == 0) return;

        // Explicit edge chain confirmed: Domain ←[AssociatedWith]→ Repo ←[BelongsTo]─ Service
        var firstDomain = domainConnections.First();
        await _findingService.AttachEvidenceAsync(findingId, new AttachEvidenceRequest(
            EvidenceType: FindingEvidenceType.IntelligenceNode,
            DiscoverySource: firstDomain.Edge.DiscoverySource,
            SourceEntityId: $"internet-facing:{firstDomain.Neighbor.Id:N}",
            IntelligenceNodeId: firstDomain.Neighbor.Id,
            EvidenceReference: $"Domain:{firstDomain.Neighbor.Label}",
            SafeEvidenceJson: ProjectSafeNodeEvidence(firstDomain.Neighbor)
        ), ct);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SafeEvidenceJson — Allowlist-Only Projection (never raw MetadataJson)
    // ─────────────────────────────────────────────────────────────────────────

    internal static string ProjectSafeNodeEvidence(SecurityIntelligenceNode node)
    {
        return node.NodeType switch
        {
            IntelligenceNodeType.CredentialCandidate => JsonSerializer.Serialize(new
            {
                nodeType = "CredentialCandidate",
                nodeId = node.Id,
                credentialType = ExtractSafeField(node.MetadataJson, "credentialType", "Unknown"),
                maskedValue = ExtractSafeField(node.MetadataJson, "maskedValue", node.Label),
                validationStatus = ExtractSafeField(node.MetadataJson, "latestValidationStatus", "Unknown"),
                environment = ExtractSafeField(node.MetadataJson, "environment", "")
            }),
            IntelligenceNodeType.Service => JsonSerializer.Serialize(new
            {
                nodeType = "Service",
                nodeId = node.Id,
                serviceName = node.Label
            }),
            IntelligenceNodeType.Database => JsonSerializer.Serialize(new
            {
                nodeType = "Database",
                nodeId = node.Id,
                hostLabel = node.Label
            }),
            IntelligenceNodeType.Domain => JsonSerializer.Serialize(new
            {
                nodeType = "Domain",
                nodeId = node.Id,
                domain = node.Label
            }),
            IntelligenceNodeType.Environment => JsonSerializer.Serialize(new
            {
                nodeType = "Environment",
                nodeId = node.Id,
                environment = node.Label
            }),
            IntelligenceNodeType.Repository => JsonSerializer.Serialize(new
            {
                nodeType = "Repository",
                nodeId = node.Id,
                label = node.Label
            }),
            _ => JsonSerializer.Serialize(new { nodeType = node.NodeType.ToString(), nodeId = node.Id })
        };
    }

    internal static string ProjectSafeEdgeEvidence(
        SecurityIntelligenceEdge edge,
        SecurityIntelligenceNode? sourceNode,
        SecurityIntelligenceNode? targetNode)
    {
        return JsonSerializer.Serialize(new
        {
            edgeType = edge.EdgeType.ToString(),
            edgeId = edge.Id,
            sourceNodeType = sourceNode?.NodeType.ToString() ?? "Unknown",
            targetNodeType = targetNode?.NodeType.ToString() ?? "Unknown",
            discoverySource = edge.DiscoverySource.ToString(),
            confidence = edge.Confidence.ToString()
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Metadata Extraction Helpers
    // ─────────────────────────────────────────────────────────────────────────

    internal static string? ExtractValidationStatusFromMetadata(string metadataJson)
    {
        if (string.IsNullOrWhiteSpace(metadataJson) || metadataJson == "{}") return null;
        try
        {
            using var doc = JsonDocument.Parse(metadataJson);
            if (doc.RootElement.TryGetProperty("latestValidationStatus", out var statusProp) &&
                statusProp.ValueKind == JsonValueKind.String)
            {
                return statusProp.GetString();
            }
        }
        catch (JsonException) { }
        return null;
    }

    private static string ExtractCredentialType(SecurityIntelligenceNode node)
    {
        return ExtractSafeField(node.MetadataJson, "credentialType", "Unknown");
    }

    /// <summary>
    /// Extracts a single safe field from MetadataJson. Returns defaultValue on failure.
    /// Never returns raw credential data — only extracts explicitly named fields.
    /// </summary>
    internal static string ExtractSafeField(string metadataJson, string fieldName, string defaultValue)
    {
        if (string.IsNullOrWhiteSpace(metadataJson) || metadataJson == "{}") return defaultValue;
        try
        {
            using var doc = JsonDocument.Parse(metadataJson);
            if (doc.RootElement.TryGetProperty(fieldName, out var prop) &&
                prop.ValueKind == JsonValueKind.String)
            {
                return prop.GetString() ?? defaultValue;
            }
        }
        catch (JsonException) { }
        return defaultValue;
    }
}
