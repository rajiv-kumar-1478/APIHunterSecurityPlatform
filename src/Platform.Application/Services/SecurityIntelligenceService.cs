using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Application.Services;


public class SecurityIntelligenceService
{
    private readonly IPlatformDbContext _dbContext;
    private readonly SecurityIntelligenceGraphBuilder _graphBuilder;
    private readonly GraphIntelligenceEngine _graphIntelligenceEngine;
    private readonly ExposureAnalysisService _exposureAnalysisService;
    private readonly ICurrentUserContext _currentUser;

    public SecurityIntelligenceService(
        IPlatformDbContext dbContext,
        SecurityIntelligenceGraphBuilder graphBuilder,
        GraphIntelligenceEngine graphIntelligenceEngine,
        ExposureAnalysisService exposureAnalysisService,
        ICurrentUserContext currentUser)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _graphBuilder = graphBuilder ?? throw new ArgumentNullException(nameof(graphBuilder));
        _graphIntelligenceEngine = graphIntelligenceEngine ?? throw new ArgumentNullException(nameof(graphIntelligenceEngine));
        _exposureAnalysisService = exposureAnalysisService ?? throw new ArgumentNullException(nameof(exposureAnalysisService));
        _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
    }

    public async Task RebuildGraphForRepositoryAsync(Guid repositoryId, CancellationToken ct = default)
    {
        var repo = await _dbContext.Repositories.FirstOrDefaultAsync(r => r.Id == repositoryId, ct)
            ?? throw new KeyNotFoundException($"Repository with ID '{repositoryId}' was not found.");

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.GraphRebuildRequested,
            UserId = _currentUser.UserId,
            ResourceType = "Repository",
            ResourceId = repositoryId.ToString(),
            Metadata = JsonSerializer.Serialize(new { repo.FullName }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);

        await _graphBuilder.BuildGraphForRepositoryAsync(repositoryId, ct);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.GraphBuildCompleted,
            UserId = _currentUser.UserId,
            ResourceType = "Repository",
            ResourceId = repositoryId.ToString(),
            Metadata = JsonSerializer.Serialize(new { repo.FullName }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });

        await _dbContext.SaveChangesAsync(ct);
    }

    public async Task AnalyzeGraphIntelligenceAsync(Guid repositoryId, CancellationToken ct = default)
    {
        var repo = await _dbContext.Repositories.FirstOrDefaultAsync(r => r.Id == repositoryId, ct)
            ?? throw new KeyNotFoundException($"Repository with ID '{repositoryId}' was not found.");

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.GraphIntelligenceAnalysisCompleted,
            UserId = _currentUser.UserId,
            ResourceType = "Repository",
            ResourceId = repositoryId.ToString(),
            Metadata = JsonSerializer.Serialize(new { repo.FullName, stage = "Started" }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });
        await _dbContext.SaveChangesAsync(ct);

        await _graphIntelligenceEngine.AnalyzeRepositoryGraphAsync(repositoryId, ct);

        _dbContext.AuditEvents.Add(new AuditEvent
        {
            EventCode = AuditEventCode.GraphIntelligenceAnalysisCompleted,
            UserId = _currentUser.UserId,
            ResourceType = "Repository",
            ResourceId = repositoryId.ToString(),
            Metadata = JsonSerializer.Serialize(new { repo.FullName, stage = "Completed" }),
            CorrelationId = _currentUser.CorrelationId ?? Guid.NewGuid().ToString()
        });
        await _dbContext.SaveChangesAsync(ct);
    }

    public async Task AnalyzeSnapshotExposureAsync(Guid repositoryId, CancellationToken ct = default)
    {
        var repo = await _dbContext.Repositories.FirstOrDefaultAsync(r => r.Id == repositoryId, ct)
            ?? throw new KeyNotFoundException($"Repository with ID '{repositoryId}' was not found.");

        await _exposureAnalysisService.AnalyzeRepositorySnapshotHistoryAsync(repositoryId, ct);
    }

    public async Task<GraphResponseDto> GetGraphAsync(Guid? repositoryId, string? nodeType, string? discoverySource, CancellationToken ct = default)
    {
        var nodesQuery = _dbContext.SecurityIntelligenceNodes.AsQueryable();
        var edgesQuery = _dbContext.SecurityIntelligenceEdges
            .Include(e => e.SourceNode)
            .Include(e => e.TargetNode)
            .AsQueryable();

        if (repositoryId.HasValue)
        {
            string repoNodeName = $"repo:{repositoryId.Value}";
            nodesQuery = nodesQuery.Where(n => n.RelatedEntityId == repositoryId.Value || n.Name == repoNodeName);
        }

        if (!string.IsNullOrWhiteSpace(nodeType) && Enum.TryParse<IntelligenceNodeType>(nodeType, true, out var parsedType))
        {
            nodesQuery = nodesQuery.Where(n => n.NodeType == parsedType);
        }

        if (!string.IsNullOrWhiteSpace(discoverySource) && Enum.TryParse<DiscoveryType>(discoverySource, true, out var parsedSource))
        {
            edgesQuery = edgesQuery.Where(e => e.DiscoverySource == parsedSource);
        }

        var nodes = await nodesQuery.ToListAsync(ct);
        var nodeIds = nodes.Select(n => n.Id).ToHashSet();

        var edges = await edgesQuery
            .Where(e => nodeIds.Contains(e.SourceNodeId) || nodeIds.Contains(e.TargetNodeId))
            .ToListAsync(ct);

        return new GraphResponseDto(
            nodes.Select(ToNodeDto).ToList(),
            edges.Select(ToEdgeDto).ToList());
    }

    public async Task<PagedResultDto<IntelligenceNodeDto>> GetNodesAsync(int page = 1, int pageSize = 20, string? nodeType = null, CancellationToken ct = default)
    {
        var query = _dbContext.SecurityIntelligenceNodes.AsQueryable();

        if (!string.IsNullOrWhiteSpace(nodeType) && Enum.TryParse<IntelligenceNodeType>(nodeType, true, out var parsedType))
        {
            query = query.Where(n => n.NodeType == parsedType);
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(n => n.LastObservedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return new PagedResultDto<IntelligenceNodeDto>(items.Select(ToNodeDto).ToList(), total, page, pageSize);
    }

    public async Task<IntelligenceNodeDetailsDto> GetNodeByIdAsync(Guid id, CancellationToken ct = default)
    {
        var node = await _dbContext.SecurityIntelligenceNodes.FirstOrDefaultAsync(n => n.Id == id, ct)
            ?? throw new KeyNotFoundException($"Intelligence node with ID '{id}' was not found.");

        var relationships = await GetNodeRelationshipsAsync(id, ct);
        return new IntelligenceNodeDetailsDto(ToNodeDto(node), relationships);
    }

    public async Task<NodeRelationshipsDto> GetNodeRelationshipsAsync(Guid nodeId, CancellationToken ct = default)
    {
        var outgoing = await _dbContext.SecurityIntelligenceEdges
            .Include(e => e.TargetNode)
            .Where(e => e.SourceNodeId == nodeId)
            .ToListAsync(ct);

        var incoming = await _dbContext.SecurityIntelligenceEdges
            .Include(e => e.SourceNode)
            .Where(e => e.TargetNodeId == nodeId)
            .ToListAsync(ct);

        return new NodeRelationshipsDto(
            outgoing.Select(ToEdgeDto).ToList(),
            incoming.Select(ToEdgeDto).ToList());
    }

    public async Task<PagedResultDto<IntelligenceEdgeDto>> GetEdgesAsync(int page = 1, int pageSize = 20, string? edgeType = null, string? discoverySource = null, CancellationToken ct = default)
    {
        var query = _dbContext.SecurityIntelligenceEdges
            .Include(e => e.SourceNode)
            .Include(e => e.TargetNode)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(edgeType) && Enum.TryParse<IntelligenceEdgeType>(edgeType, true, out var parsedEdge))
        {
            query = query.Where(e => e.EdgeType == parsedEdge);
        }

        if (!string.IsNullOrWhiteSpace(discoverySource) && Enum.TryParse<DiscoveryType>(discoverySource, true, out var parsedSource))
        {
            query = query.Where(e => e.DiscoverySource == parsedSource);
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(e => e.LastObservedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return new PagedResultDto<IntelligenceEdgeDto>(items.Select(ToEdgeDto).ToList(), total, page, pageSize);
    }

    private static IntelligenceNodeDto ToNodeDto(SecurityIntelligenceNode node)
    {
        return new IntelligenceNodeDto(
            node.Id,
            node.NodeType.ToString(),
            node.Name,
            node.Label,
            node.RelatedEntityId,
            node.MetadataJson,
            node.FirstObservedAtUtc,
            node.LastObservedAtUtc);
    }

    private static IntelligenceEdgeDto ToEdgeDto(SecurityIntelligenceEdge edge)
    {
        return new IntelligenceEdgeDto(
            edge.Id,
            edge.SourceNodeId,
            edge.SourceNode?.Name ?? string.Empty,
            edge.TargetNodeId,
            edge.TargetNode?.Name ?? string.Empty,
            edge.EdgeType.ToString(),
            edge.DiscoverySource.ToString(),
            edge.Confidence.ToString(),
            edge.EvidenceReference,
            edge.FirstObservedAtUtc,
            edge.LastObservedAtUtc);
    }
}

public record RebuildGraphRequest(Guid RepositoryId);

public record GraphResponseDto(
    List<IntelligenceNodeDto> Nodes,
    List<IntelligenceEdgeDto> Edges);

public record IntelligenceNodeDto(
    Guid Id,
    string NodeType,
    string Name,
    string Label,
    Guid? RelatedEntityId,
    string MetadataJson,
    DateTime FirstObservedAtUtc,
    DateTime LastObservedAtUtc);

public record IntelligenceEdgeDto(
    Guid Id,
    Guid SourceNodeId,
    string SourceNodeName,
    Guid TargetNodeId,
    string TargetNodeName,
    string EdgeType,
    string DiscoverySource,
    string Confidence,
    string EvidenceReference,
    DateTime FirstObservedAtUtc,
    DateTime LastObservedAtUtc);

public record NodeRelationshipsDto(
    List<IntelligenceEdgeDto> OutgoingEdges,
    List<IntelligenceEdgeDto> IncomingEdges);

public record IntelligenceNodeDetailsDto(
    IntelligenceNodeDto Node,
    NodeRelationshipsDto Relationships);

public record PagedResultDto<T>(
    List<T> Items,
    int TotalCount,
    int Page,
    int PageSize);
