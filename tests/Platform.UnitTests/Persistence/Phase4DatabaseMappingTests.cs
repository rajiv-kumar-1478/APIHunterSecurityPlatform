using Microsoft.EntityFrameworkCore;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Persistence;

public class Phase4DatabaseMappingTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;

    public Phase4DatabaseMappingTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("Phase4DbMappingTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task CanPersistMultipleModelsForSameProvider()
    {
        var config1 = new AiProviderConfig
        {
            ProviderName = "OpenAI",
            ModelName = "gpt-4o",
            IsEnabled = true,
            Priority = 100,
            EncryptedApiKey = "EncryptedKey1"
        };

        var config2 = new AiProviderConfig
        {
            ProviderName = "OpenAI",
            ModelName = "gpt-4o-mini",
            IsEnabled = true,
            Priority = 80,
            EncryptedApiKey = "EncryptedKey2"
        };

        _dbContext.AiProviderConfigs.AddRange(config1, config2);
        await _dbContext.SaveChangesAsync();

        var retrieved = await _dbContext.AiProviderConfigs
            .Where(p => p.ProviderName == "OpenAI")
            .OrderByDescending(p => p.Priority)
            .ToListAsync();

        Assert.Equal(2, retrieved.Count);
        Assert.Equal("gpt-4o", retrieved[0].ModelName);
        Assert.Equal("gpt-4o-mini", retrieved[1].ModelName);
    }

    [Fact]
    public async Task DeletingInvestigationJobDeletesCheckpointsButPreservesPermanentEvidence()
    {
        var repo = new Repository
        {
            Provider = "GitHub",
            ProviderRepoId = 1001L,
            Owner = "test-org",
            Name = "backend",
            FullName = "test-org/backend",
            Url = "https://github.com/test-org/backend"
        };
        _dbContext.Repositories.Add(repo);

        var snapshot = new RepositorySnapshot
        {
            RepositoryId = repo.Id,
            CommitSha = "abc1234567890def1234567890def1234567890d",
            BranchName = "main"
        };
        _dbContext.RepositorySnapshots.Add(snapshot);
        await _dbContext.SaveChangesAsync();

        var job = new AiInvestigationJob
        {
            RepositoryId = repo.Id,
            SnapshotId = snapshot.Id,
            CurrentStage = AiInvestigationStageType.ApiHunterSeedInvestigation,
            CompletedStagesCount = 4,
            ActiveProviderName = "Groq",
            ActiveModelName = "llama-3.3-70b-versatile"
        };
        _dbContext.AiInvestigationJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        var checkpoint = new AiInvestigationCheckpoint
        {
            InvestigationJobId = job.Id,
            StageType = AiInvestigationStageType.ApiHunterSeedInvestigation,
            CursorPosition = "file_index_4",
            DurableResultJson = "{\"seed_processed\": true}"
        };
        _dbContext.AiInvestigationCheckpoints.Add(checkpoint);

        var evidence = new AiInvestigationEvidence
        {
            InvestigationId = job.Id,
            SnapshotId = snapshot.Id,
            EvidenceType = "DatabaseConfig",
            FilePath = "docker-compose.yml",
            StartLine = 20,
            EndLine = 28,
            Confidence = FindingConfidence.High,
            EvidenceJson = "{\"db_type\": \"PostgreSQL\"}"
        };
        _dbContext.AiInvestigationEvidences.Add(evidence);
        await _dbContext.SaveChangesAsync();

        // Perform Job Cleanup / Deletion
        _dbContext.AiInvestigationJobs.Remove(job);
        await _dbContext.SaveChangesAsync();

        // Checkpoint must be cascade-deleted
        var retrievedCheckpoint = await _dbContext.AiInvestigationCheckpoints.FirstOrDefaultAsync(c => c.Id == checkpoint.Id);
        Assert.Null(retrievedCheckpoint);

        // Evidence MUST STILL EXIST in database (anchored to Snapshot)
        var retrievedEvidence = await _dbContext.AiInvestigationEvidences.FirstOrDefaultAsync(e => e.Id == evidence.Id);
        Assert.NotNull(retrievedEvidence);
        Assert.Null(retrievedEvidence.InvestigationId); // Nullified FK provenance
        Assert.Equal(snapshot.Id, retrievedEvidence.SnapshotId); // Still anchored to Snapshot
        Assert.Equal("docker-compose.yml", retrievedEvidence.FilePath);
    }

    [Fact]
    public async Task CanPersistSecurityIntelligenceGraphNodesAndEdgesWithProvenance()
    {
        var node1 = new SecurityIntelligenceNode { NodeType = IntelligenceNodeType.Repository, Name = "test-org/backend", Label = "Backend Service" };
        var node2 = new SecurityIntelligenceNode { NodeType = IntelligenceNodeType.Service, Name = "PostgreSQL DB", Label = "Production Database" };

        _dbContext.SecurityIntelligenceNodes.AddRange(node1, node2);
        await _dbContext.SaveChangesAsync();

        var edge = new SecurityIntelligenceEdge
        {
            SourceNodeId = node1.Id,
            TargetNodeId = node2.Id,
            EdgeType = IntelligenceEdgeType.UsedBy,
            DiscoverySource = DiscoveryType.AiInvestigator,
            Confidence = FindingConfidence.High,
            EvidenceReference = "Investigation #42 (docker-compose.yml:L20-28)"
        };
        _dbContext.SecurityIntelligenceEdges.Add(edge);
        await _dbContext.SaveChangesAsync();

        var retrievedEdge = await _dbContext.SecurityIntelligenceEdges
            .Include(e => e.SourceNode)
            .Include(e => e.TargetNode)
            .FirstOrDefaultAsync(e => e.Id == edge.Id);

        Assert.NotNull(retrievedEdge);
        Assert.Equal("test-org/backend", retrievedEdge.SourceNode.Name);
        Assert.Equal("PostgreSQL DB", retrievedEdge.TargetNode.Name);
        Assert.Equal(DiscoveryType.AiInvestigator, retrievedEdge.DiscoverySource);
    }
}
