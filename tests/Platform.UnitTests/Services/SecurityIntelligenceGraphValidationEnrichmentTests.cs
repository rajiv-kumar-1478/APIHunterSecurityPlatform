using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class SecurityIntelligenceGraphValidationEnrichmentTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly SecurityIntelligenceGraphBuilder _graphBuilder;

    public SecurityIntelligenceGraphValidationEnrichmentTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("Phase5GraphEnrichmentTestDb_" + Guid.NewGuid())
            .Options;

        _dbContext = new PlatformDbContext(options);
        var loggerMock = new Mock<ILogger<SecurityIntelligenceGraphBuilder>>();
        _graphBuilder = new SecurityIntelligenceGraphBuilder(_dbContext, loggerMock.Object);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task BuildGraph_EnrichesCandidateNodesWithValidationProvenanceWithoutMutatingDiscoverySources()
    {
        // 1. Setup Repository, Snapshot, File, and Candidate
        var repo = new Repository { FullName = "test-org/secure-service", Provider = "GitHub", Url = "https://github.com/test-org/secure-service" };
        var snapshot = new RepositorySnapshot { Repository = repo, CommitSha = "abc1234", AnalysisStatus = AnalysisStatus.Completed };
        var file = new SnapshotFile { Snapshot = snapshot, FilePath = "config/settings.json", ContentHash = "hash1" };

        var candidate = new CredentialCandidate
        {
            CredentialType = "OpenAI",
            MaskedValue = "sk-live-****1234",
            EncryptedRawValue = "secret_enc_payload",
            Status = CandidateStatus.Detected
        };

        var occurrence = new CandidateOccurrence
        {
            Candidate = candidate,
            SnapshotFile = file,
            Repository = repo,
            LineNumber = 12,
            Confidence = "High"
        };

        _dbContext.Repositories.Add(repo);
        _dbContext.RepositorySnapshots.Add(snapshot);
        _dbContext.SnapshotFiles.Add(file);
        _dbContext.CredentialCandidates.Add(candidate);
        _dbContext.CandidateOccurrences.Add(occurrence);
        await _dbContext.SaveChangesAsync();

        // 2. Add Validation Result (Phase 5)
        var valResult1 = new CredentialValidationResult
        {
            CandidateId = candidate.Id,
            ProviderName = "OpenAI",
            Status = ValidationStatus.Valid,
            Confidence = ValidationConfidence.Confirmed,
            ResponseClassification = "HTTP 200 OK — Models Catalog",
            SafeEvidenceJson = "{\"modelsCount\":10}",
            ValidatedAtUtc = DateTime.UtcNow.AddMinutes(-10)
        };
        _dbContext.CredentialValidationResults.Add(valResult1);
        await _dbContext.SaveChangesAsync();

        // 3. Execute Graph Building
        await _graphBuilder.BuildGraphForRepositoryAsync(repo.Id);

        // 4. Assert Graph Enrichment & Provenance
        var candNode = await _dbContext.SecurityIntelligenceNodes
            .FirstOrDefaultAsync(n => n.NodeType == IntelligenceNodeType.CredentialCandidate && n.Name == $"candidate:{candidate.Id}");

        Assert.NotNull(candNode);
        Assert.Contains("OpenAI", candNode.Label);
        Assert.Contains("Valid", candNode.Label);
        Assert.DoesNotContain("secret_enc_payload", candNode.MetadataJson);

        using var doc1 = JsonDocument.Parse(candNode.MetadataJson);
        Assert.True(doc1.RootElement.GetProperty("isCurrentlyValidated").GetBoolean());
        Assert.Equal("Valid", doc1.RootElement.GetProperty("latestValidationStatus").GetString());

        // Assert Validation Evidence is enriched on candidate edge
        var repoNode = await _dbContext.SecurityIntelligenceNodes
            .FirstAsync(n => n.NodeType == IntelligenceNodeType.Repository && n.Name == $"repo:{repo.Id}");

        var candEdge = await _dbContext.SecurityIntelligenceEdges
            .FirstOrDefaultAsync(e => e.SourceNodeId == candNode.Id && e.TargetNodeId == repoNode.Id);

        Assert.NotNull(candEdge);
        Assert.Contains("Validation Result #", candEdge.EvidenceReference);
        Assert.Equal(FindingConfidence.High, candEdge.Confidence);



        // Assert Candidate.Status remains untouched (Detected!)
        var fetchedCand = await _dbContext.CredentialCandidates.FirstAsync(c => c.Id == candidate.Id);
        Assert.Equal(CandidateStatus.Detected, fetchedCand.Status);
    }

    [Fact]
    public async Task BuildGraph_UpdatesValidationStateToInvalidWhenRevalidationFails()
    {
        var repo = new Repository { FullName = "test-org/payment-gateway", Provider = "GitHub", Url = "https://github.com/test-org/payment-gateway" };
        var snapshot = new RepositorySnapshot { Repository = repo, CommitSha = "def5678", AnalysisStatus = AnalysisStatus.Completed };
        var file = new SnapshotFile { Snapshot = snapshot, FilePath = "src/stripe.ts", ContentHash = "hash2" };

        var candidate = new CredentialCandidate
        {
            CredentialType = "Stripe",
            MaskedValue = "sk_live_****5678",
            EncryptedRawValue = "secret_enc_stripe",
            Status = CandidateStatus.Triaged
        };

        var occurrence = new CandidateOccurrence
        {
            Candidate = candidate,
            SnapshotFile = file,
            Repository = repo,
            LineNumber = 45,
            Confidence = "High"
        };

        _dbContext.Repositories.Add(repo);
        _dbContext.RepositorySnapshots.Add(snapshot);
        _dbContext.SnapshotFiles.Add(file);
        _dbContext.CredentialCandidates.Add(candidate);
        _dbContext.CandidateOccurrences.Add(occurrence);
        await _dbContext.SaveChangesAsync();

        // Attempt 1: Valid
        var result1 = new CredentialValidationResult
        {
            CandidateId = candidate.Id,
            ProviderName = "Stripe",
            Status = ValidationStatus.Valid,
            Confidence = ValidationConfidence.Confirmed,
            ValidatedAtUtc = DateTime.UtcNow.AddHours(-2)
        };
        _dbContext.CredentialValidationResults.Add(result1);
        await _dbContext.SaveChangesAsync();

        await _graphBuilder.BuildGraphForRepositoryAsync(repo.Id);

        // Attempt 2: Re-validation result = Revoked
        var result2 = new CredentialValidationResult
        {
            CandidateId = candidate.Id,
            ProviderName = "Stripe",
            Status = ValidationStatus.Revoked,
            Confidence = ValidationConfidence.Confirmed,
            ValidatedAtUtc = DateTime.UtcNow
        };
        _dbContext.CredentialValidationResults.Add(result2);
        await _dbContext.SaveChangesAsync();

        // Re-build graph
        await _graphBuilder.BuildGraphForRepositoryAsync(repo.Id);

        // Assert node metadata reflects Revoked state (isCurrentlyValidated = false)
        var candNode = await _dbContext.SecurityIntelligenceNodes
            .FirstOrDefaultAsync(n => n.NodeType == IntelligenceNodeType.CredentialCandidate && n.Name == $"candidate:{candidate.Id}");

        Assert.NotNull(candNode);
        using var doc = JsonDocument.Parse(candNode.MetadataJson);
        Assert.False(doc.RootElement.GetProperty("isCurrentlyValidated").GetBoolean());
        Assert.Equal("Revoked", doc.RootElement.GetProperty("latestValidationStatus").GetString());

        // Both historical validation records must remain queryable in DB!
        var history = await _dbContext.CredentialValidationResults
            .Where(r => r.CandidateId == candidate.Id)
            .ToListAsync();
        Assert.Equal(2, history.Count);

        // CandidateStatus remains Triaged
        var fetchedCand = await _dbContext.CredentialCandidates.FirstAsync(c => c.Id == candidate.Id);
        Assert.Equal(CandidateStatus.Triaged, fetchedCand.Status);
    }
}
