using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Persistence;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Platform.Infrastructure.Services;
using Xunit;

namespace Platform.UnitTests.Services;

public class SecurityIntelligenceGraphTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly Mock<ILogger<SecurityIntelligenceGraphBuilder>> _mockBuilderLogger;
    private readonly Mock<ICurrentUserContext> _mockUserContext;

    public SecurityIntelligenceGraphTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("IntelligenceGraphDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        _mockBuilderLogger = new Mock<ILogger<SecurityIntelligenceGraphBuilder>>();
        _mockUserContext = new Mock<ICurrentUserContext>();
        _mockUserContext.Setup(u => u.UserId).Returns(Guid.NewGuid());
        _mockUserContext.Setup(u => u.CorrelationId).Returns("test-corr-id");
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    private async Task<Repository> SeedRepositoryAsync()
    {
        var repo = new Repository { FullName = "octocat/graph-demo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();
        return repo;
    }

    [Fact]
    public void Normalization_Domain_Host_Service_Environment_NormalizesCleanly()
    {
        Assert.Equal("example.com", SecurityIntelligenceGraphBuilder.NormalizeDomain("https://EXAMPLE.COM/api/v1?test=1"));
        Assert.Equal("postgres.internal", SecurityIntelligenceGraphBuilder.NormalizeHost("  POSTGRES.INTERNAL/  "));
        Assert.Equal("web-api", SecurityIntelligenceGraphBuilder.NormalizeServiceName(" Web_API "));
        Assert.Equal("production", SecurityIntelligenceGraphBuilder.NormalizeEnvironment("PROD_LIVE"));
        Assert.Equal("staging", SecurityIntelligenceGraphBuilder.NormalizeEnvironment("staging_env"));
    }

    [Fact]
    public async Task NodeIdentityAndDeduplication_SameEntity_ReturnsSameNodeWithoutDuplicates()
    {
        var builder = new SecurityIntelligenceGraphBuilder(_dbContext, _mockBuilderLogger.Object);

        var node1 = await builder.GetOrCreateNodeAsync(IntelligenceNodeType.Domain, "domain:example.com", "example.com", null, "{}", CancellationToken.None);
        var node2 = await builder.GetOrCreateNodeAsync(IntelligenceNodeType.Domain, "domain:example.com", "example.com", null, "{}", CancellationToken.None);

        Assert.Equal(node1.Id, node2.Id);

        var totalNodes = await _dbContext.SecurityIntelligenceNodes.CountAsync();
        Assert.Equal(1, totalNodes);
    }

    [Fact]
    public async Task EdgeIdentityAndDeduplication_SameRelationship_UpdatesLastObservedWithoutDuplicates()
    {
        var builder = new SecurityIntelligenceGraphBuilder(_dbContext, _mockBuilderLogger.Object);

        var nodeA = await builder.GetOrCreateNodeAsync(IntelligenceNodeType.Repository, "repo:1", "repo1", Guid.NewGuid(), "{}", CancellationToken.None);
        var nodeB = await builder.GetOrCreateNodeAsync(IntelligenceNodeType.Domain, "domain:example.com", "example.com", null, "{}", CancellationToken.None);

        var edge1 = await builder.UpsertEdgeAsync(nodeA.Id, nodeB.Id, IntelligenceEdgeType.AssociatedWith, DiscoveryType.AiInvestigator, FindingConfidence.Medium, "Evidence #1", CancellationToken.None);
        var edge2 = await builder.UpsertEdgeAsync(nodeA.Id, nodeB.Id, IntelligenceEdgeType.AssociatedWith, DiscoveryType.DeterministicDetector, FindingConfidence.High, "Evidence #2", CancellationToken.None);

        Assert.Equal(edge1.Id, edge2.Id);
        Assert.Equal(FindingConfidence.High, edge2.Confidence); // Cross-source enrichment upgraded confidence to High
        Assert.Contains("Evidence #1", edge2.EvidenceReference);
        Assert.Contains("Evidence #2", edge2.EvidenceReference);

        var totalEdges = await _dbContext.SecurityIntelligenceEdges.CountAsync();
        Assert.Equal(1, totalEdges);
    }

    [Fact]
    public async Task Provenance_PreservesApiHunter_Deterministic_AndAiSources()
    {
        var repo = await SeedRepositoryAsync();
        var builder = new SecurityIntelligenceGraphBuilder(_dbContext, _mockBuilderLogger.Object);

        // Seed APIHunter evidence
        var record = new ApiHunterRecord { SearchProvider = "GitHub", Status = PlatformKeyStatus.Valid, MaskedKey = "sk-live-****1234" };
        var repoRef = new ApiHunterRepoReference { ApiHunterRecord = record, RepoName = repo.FullName, FilePath = ".env", LineNumber = 5 };
        _dbContext.ApiHunterRecords.Add(record);
        _dbContext.ApiHunterRepoReferences.Add(repoRef);

        // Seed Deterministic Candidate
        var candidate = new CredentialCandidate { CredentialType = "OpenAI", MaskedValue = "sk-live-****1234" };
        var occurrence = new CandidateOccurrence { Candidate = candidate, RepositoryId = repo.Id, LineNumber = 5 };


        _dbContext.CredentialCandidates.Add(candidate);
        _dbContext.CandidateOccurrences.Add(occurrence);

        // Seed AI Evidence
        var snapshot = new RepositorySnapshot { RepositoryId = repo.Id, CommitSha = "123456" };
        var aiEvidence = new AiInvestigationEvidence
        {
            Snapshot = snapshot,
            EvidenceType = "CrossFileRelationship",
            FilePath = ".env",
            Source = DiscoveryType.AiInvestigator,
            EvidenceJson = "{\"domain\":\"api.stripe.com\",\"environment\":\"production\"}"
        };
        _dbContext.RepositorySnapshots.Add(snapshot);
        _dbContext.AiInvestigationEvidences.Add(aiEvidence);

        await _dbContext.SaveChangesAsync();

        // Build Graph
        await builder.BuildGraphForRepositoryAsync(repo.Id);

        var edges = await _dbContext.SecurityIntelligenceEdges.ToListAsync();
        Assert.Contains(edges, e => e.DiscoverySource == DiscoveryType.ApiHunterSync);
        Assert.Contains(edges, e => e.DiscoverySource == DiscoveryType.DeterministicDetector);
        Assert.Contains(edges, e => e.DiscoverySource == DiscoveryType.AiInvestigator);
    }

    [Fact]
    public async Task SecurityIntelligenceService_QueryNodesEdgesAndRebuild_Succeeds()
    {
        var repo = await SeedRepositoryAsync();
        var builder = new SecurityIntelligenceGraphBuilder(_dbContext, _mockBuilderLogger.Object);
        var findingService = new SecurityFindingService(_dbContext, new Platform.Application.Services.RiskEngine(new Platform.Application.Configuration.RiskPolicyOptions()), new Mock<ILogger<SecurityFindingService>>().Object);
        var graphEngine = new GraphIntelligenceEngine(_dbContext, findingService, new Mock<ILogger<GraphIntelligenceEngine>>().Object);
        var exposureService = new ExposureAnalysisService(_dbContext, findingService, new Mock<ILogger<ExposureAnalysisService>>().Object);
        var service = new SecurityIntelligenceService(_dbContext, builder, graphEngine, exposureService, _mockUserContext.Object);

        // Rebuild graph
        await service.RebuildGraphForRepositoryAsync(repo.Id);

        // Query graph
        var graph = await service.GetGraphAsync(repo.Id, null, null);
        Assert.NotNull(graph);
        Assert.NotEmpty(graph.Nodes);

        var nodesPaged = await service.GetNodesAsync(1, 10, null);
        Assert.NotNull(nodesPaged);
        Assert.True(nodesPaged.TotalCount > 0);

        var audit = await _dbContext.AuditEvents.FirstOrDefaultAsync(a => a.EventCode == AuditEventCode.GraphBuildCompleted);
        Assert.NotNull(audit);
    }
}
