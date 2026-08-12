using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Services;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Services;

public class GraphIntelligenceEngineTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;
    private readonly GraphIntelligenceEngine _engine;

    public GraphIntelligenceEngineTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("GraphIntelligenceDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        var riskPolicy = new RiskPolicyOptions();
        var riskEngine = new RiskEngine(riskPolicy);
        _findingService = new SecurityFindingService(
            _dbContext, riskEngine, new Mock<ILogger<SecurityFindingService>>().Object);
        _engine = new GraphIntelligenceEngine(
            _dbContext, _findingService, new Mock<ILogger<GraphIntelligenceEngine>>().Object);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers: Graph Seeding
    // ─────────────────────────────────────────────────────────────────────────

    private async Task<(Repository repo, SecurityIntelligenceNode repoNode)> SeedRepoWithGraphNodeAsync(string repoName = "octocat/test-repo")
    {
        var repo = new Repository { FullName = repoName };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        var repoNode = new SecurityIntelligenceNode
        {
            NodeType = IntelligenceNodeType.Repository,
            Name = $"repo:{repo.Id}",
            Label = repoName,
            RelatedEntityId = repo.Id,
            MetadataJson = JsonSerializer.Serialize(new { Provider = "GitHub", Url = $"https://github.com/{repoName}" })
        };
        _dbContext.SecurityIntelligenceNodes.Add(repoNode);
        await _dbContext.SaveChangesAsync();

        return (repo, repoNode);
    }

    private async Task<SecurityIntelligenceNode> AddNodeAsync(IntelligenceNodeType type, string name, string label, Guid? relatedEntityId = null, string metadataJson = "{}")
    {
        var node = new SecurityIntelligenceNode
        {
            NodeType = type,
            Name = name,
            Label = label,
            RelatedEntityId = relatedEntityId,
            MetadataJson = metadataJson
        };
        _dbContext.SecurityIntelligenceNodes.Add(node);
        await _dbContext.SaveChangesAsync();
        return node;
    }

    private async Task<SecurityIntelligenceEdge> AddEdgeAsync(
        Guid sourceId, Guid targetId,
        IntelligenceEdgeType edgeType,
        DiscoveryType discoverySource = DiscoveryType.AiInvestigator,
        FindingConfidence confidence = FindingConfidence.High)
    {
        var edge = new SecurityIntelligenceEdge
        {
            SourceNodeId = sourceId,
            TargetNodeId = targetId,
            EdgeType = edgeType,
            DiscoverySource = discoverySource,
            Confidence = confidence,
            EvidenceReference = $"Test Edge {edgeType}"
        };
        _dbContext.SecurityIntelligenceEdges.Add(edge);
        await _dbContext.SaveChangesAsync();
        return edge;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: ValidatedCredentialExposed Pattern
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test1_ValidatedCredentialExposed_CreatesFindinWithNodeEvidence()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        // Credential node with Valid status
        var candNode = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "OpenAI (sk-****1234) [Valid]",
            repo.Id,
            JsonSerializer.Serialize(new
            {
                credentialType = "OpenAI",
                latestValidationStatus = "Valid",
                maskedValue = "sk-****1234"
            }));

        // Credential discovered in repo
        await AddEdgeAsync(candNode.Id, repoNode.Id, IntelligenceEdgeType.AppearsIn, DiscoveryType.DeterministicDetector);

        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.Include(f => f.Evidences).ToListAsync();
        Assert.Contains(findings, f => f.FindingType == FindingType.ValidatedCredentialExposed);

        var finding = findings.First(f => f.FindingType == FindingType.ValidatedCredentialExposed);
        Assert.Equal(repo.Id, finding.RepositoryId);
        Assert.True(finding.RiskScore > 0);
        Assert.NotEmpty(finding.Evidences);
        Assert.Contains(finding.Evidences, e => e.EvidenceType == FindingEvidenceType.IntelligenceNode && e.IntelligenceNodeId == candNode.Id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: ProductionServiceExposed Pattern
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test2_ProductionServiceExposed_CreatesFindinWithServiceAndEnvEvidence()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        var serviceNode = await AddNodeAsync(
            IntelligenceNodeType.Service,
            $"service:{repo.Id}:stripe-api",
            "stripe-api",
            repo.Id,
            JsonSerializer.Serialize(new { serviceName = "stripe-api" }));

        var envNode = await AddNodeAsync(
            IntelligenceNodeType.Environment,
            $"env:{repo.Id}:production",
            "production",
            repo.Id,
            JsonSerializer.Serialize(new { environment = "production" }));

        // Service → Repo (BelongsTo)
        await AddEdgeAsync(serviceNode.Id, repoNode.Id, IntelligenceEdgeType.BelongsTo);
        // Repo → Environment (AssociatedWith)
        await AddEdgeAsync(repoNode.Id, envNode.Id, IntelligenceEdgeType.AssociatedWith);

        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.Include(f => f.Evidences).ToListAsync();
        Assert.Contains(findings, f => f.FindingType == FindingType.ProductionServiceExposed);

        var finding = findings.First(f => f.FindingType == FindingType.ProductionServiceExposed);
        Assert.Contains(finding.Evidences, e => e.IntelligenceNodeId == serviceNode.Id);
        Assert.Contains(finding.Evidences, e => e.IntelligenceNodeId == envNode.Id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: DatabaseExposure Pattern
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test3_DatabaseExposure_CreatesFindinWithDbAndCredentialEvidence()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        var dbNode = await AddNodeAsync(
            IntelligenceNodeType.Database,
            "db:db.example.com",
            "db.example.com",
            null,
            JsonSerializer.Serialize(new { host = "db.example.com" }));

        var candNode = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "PostgreSQL (pg-****5678)",
            repo.Id,
            JsonSerializer.Serialize(new { credentialType = "PostgreSQL" }));

        // Repo → Database (RelatedTo)
        await AddEdgeAsync(repoNode.Id, dbNode.Id, IntelligenceEdgeType.RelatedTo);
        // Credential → Repo (AppearsIn)
        await AddEdgeAsync(candNode.Id, repoNode.Id, IntelligenceEdgeType.AppearsIn, DiscoveryType.DeterministicDetector);

        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.Include(f => f.Evidences).ToListAsync();
        Assert.Contains(findings, f => f.FindingType == FindingType.DatabaseExposure);

        var finding = findings.First(f => f.FindingType == FindingType.DatabaseExposure);
        Assert.Contains(finding.Evidences, e => e.IntelligenceNodeId == dbNode.Id);
        Assert.Contains(finding.Evidences, e => e.IntelligenceNodeId == candNode.Id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: UnvalidatedCredentialExposed Pattern
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test4_UnvalidatedCredentialExposed_CreatesFindinForCredentialWithoutValidation()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        // Credential node with NO validation metadata
        var candNode = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "GitHub (ghp_****abcd)",
            repo.Id,
            JsonSerializer.Serialize(new { credentialType = "GitHub" }));

        await AddEdgeAsync(candNode.Id, repoNode.Id, IntelligenceEdgeType.AppearsIn, DiscoveryType.DeterministicDetector);

        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.Include(f => f.Evidences).ToListAsync();
        Assert.Contains(findings, f => f.FindingType == FindingType.UnvalidatedCredentialExposed);

        var finding = findings.First(f => f.FindingType == FindingType.UnvalidatedCredentialExposed);
        Assert.Equal(repo.Id, finding.RepositoryId);
        Assert.Contains(finding.Evidences, e => e.IntelligenceNodeId == candNode.Id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Idempotency — Run Twice, No Duplicate Findings
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test5_Idempotency_RunTwice_NoDuplicateFindings()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        var candNode = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "Stripe (rk_****wxyz) [Valid]",
            repo.Id,
            JsonSerializer.Serialize(new
            {
                credentialType = "Stripe",
                latestValidationStatus = "Valid",
                maskedValue = "rk_****wxyz"
            }));

        await AddEdgeAsync(candNode.Id, repoNode.Id, IntelligenceEdgeType.AppearsIn);

        // First run
        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);
        var countAfterFirst = await _dbContext.SecurityFindings.CountAsync();
        var firstFinding = await _dbContext.SecurityFindings.FirstAsync();
        var firstObserved = firstFinding.LastObservedAtUtc;

        // Small delay to distinguish timestamps
        await Task.Delay(50);

        // Second run
        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);
        var countAfterSecond = await _dbContext.SecurityFindings.CountAsync();

        Assert.Equal(countAfterFirst, countAfterSecond);

        // LastObservedAtUtc should have been updated
        var updatedFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.Id == firstFinding.Id);
        Assert.True(updatedFinding.LastObservedAtUtc >= firstObserved);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Evidence Graph References — Correct Foreign Keys
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test6_Evidence_GraphReferences_CorrectForeignKeys()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        var serviceNode = await AddNodeAsync(
            IntelligenceNodeType.Service,
            $"service:{repo.Id}:aws-s3",
            "aws-s3",
            repo.Id);

        var envNode = await AddNodeAsync(
            IntelligenceNodeType.Environment,
            $"env:{repo.Id}:production",
            "production",
            repo.Id);

        await AddEdgeAsync(serviceNode.Id, repoNode.Id, IntelligenceEdgeType.BelongsTo);
        var envEdge = await AddEdgeAsync(repoNode.Id, envNode.Id, IntelligenceEdgeType.AssociatedWith);

        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var evidences = await _dbContext.SecurityFindingEvidences.ToListAsync();

        // All IntelligenceNode evidence must have IntelligenceNodeId set
        var nodeEvidences = evidences.Where(e => e.EvidenceType == FindingEvidenceType.IntelligenceNode).ToList();
        Assert.All(nodeEvidences, e => Assert.NotNull(e.IntelligenceNodeId));

        // All IntelligenceEdge evidence must have IntelligenceEdgeId set
        var edgeEvidences = evidences.Where(e => e.EvidenceType == FindingEvidenceType.IntelligenceEdge).ToList();
        foreach (var e in edgeEvidences)
        {
            Assert.NotNull(e.IntelligenceEdgeId);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: SafeEvidenceJson — No Secret Leak
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test7_SafeEvidenceJson_NoSecretLeak()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        // Include realistic credential patterns in metadata to test that they don't leak through
        var candNode = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "OpenAI (sk-****1234) [Valid]",
            repo.Id,
            JsonSerializer.Serialize(new
            {
                credentialType = "OpenAI",
                latestValidationStatus = "Valid",
                maskedValue = "sk-****1234",
                // These should NOT appear in SafeEvidenceJson
                rawKey = "sk-proj-abc123def456ghi789",
                secretApiKey = "AKIA1234567890ABCDEF"
            }));

        await AddEdgeAsync(candNode.Id, repoNode.Id, IntelligenceEdgeType.AppearsIn);

        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var evidences = await _dbContext.SecurityFindingEvidences.ToListAsync();
        Assert.NotEmpty(evidences);

        string[] secretPatterns = new[]
        {
            "sk-proj-", "AKIA", "ghp_", "glpat-", "SG.", "key-",
            "sk-proj-abc123", "AKIA1234567890ABCDEF",
            "rawKey", "secretApiKey"
        };

        foreach (var ev in evidences)
        {
            foreach (var pattern in secretPatterns)
            {
                Assert.DoesNotContain(pattern, ev.SafeEvidenceJson);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8: Empty Graph — Zero Findings, No Exceptions
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test8_EmptyGraph_ZeroFindings_NoExceptions()
    {
        var repo = new Repository { FullName = "octocat/empty-repo" };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();

        // No graph nodes at all
        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.ToListAsync();
        Assert.Empty(findings);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9: Risk Score Reflects Graph Context
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test9_RiskScore_ReflectsGraphContextFactors()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        // Validated credential
        var candNode = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "AWS (AKIA****DEFG) [Valid]",
            repo.Id,
            JsonSerializer.Serialize(new
            {
                credentialType = "AWS",
                latestValidationStatus = "Valid",
                maskedValue = "AKIA****DEFG"
            }));

        var envNode = await AddNodeAsync(
            IntelligenceNodeType.Environment,
            $"env:{repo.Id}:production",
            "production",
            repo.Id);

        var domainNode = await AddNodeAsync(
            IntelligenceNodeType.Domain,
            "domain:api.example.com",
            "api.example.com");

        var serviceNode = await AddNodeAsync(
            IntelligenceNodeType.Service,
            $"service:{repo.Id}:backend-api",
            "backend-api",
            repo.Id);

        // Build edges: Candidate → Repo, Service → Repo (BelongsTo), Repo → Env, Repo → Domain
        await AddEdgeAsync(candNode.Id, repoNode.Id, IntelligenceEdgeType.AppearsIn, DiscoveryType.DeterministicDetector);
        await AddEdgeAsync(serviceNode.Id, repoNode.Id, IntelligenceEdgeType.BelongsTo);
        await AddEdgeAsync(repoNode.Id, envNode.Id, IntelligenceEdgeType.AssociatedWith);
        await AddEdgeAsync(repoNode.Id, domainNode.Id, IntelligenceEdgeType.AssociatedWith);

        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);

        var finding = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .FirstOrDefaultAsync(f => f.FindingType == FindingType.ValidatedCredentialExposed);

        Assert.NotNull(finding);
        // ValidatedCredentialExposed base=40 + evidence factors should produce a meaningful score
        Assert.True(finding!.RiskScore >= 40, $"Expected RiskScore >= 40, got {finding.RiskScore}");

        // Verify breakdown JSON contains algorithm version
        Assert.Contains("\"algorithmVersion\"", finding.RiskFactorBreakdownJson);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 10: Cross-Repository Isolation
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test10_CrossRepository_Isolation()
    {
        // Repo A with Credential → Service A
        var (repoA, repoNodeA) = await SeedRepoWithGraphNodeAsync("org/repo-a");

        var candNodeA = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "OpenAI (sk-****aaaa) [Valid]",
            repoA.Id,
            JsonSerializer.Serialize(new
            {
                credentialType = "OpenAI",
                latestValidationStatus = "Valid",
                maskedValue = "sk-****aaaa"
            }));

        await AddEdgeAsync(candNodeA.Id, repoNodeA.Id, IntelligenceEdgeType.AppearsIn);

        // Repo B with Service B → Database B (completely separate graph)
        var (repoB, repoNodeB) = await SeedRepoWithGraphNodeAsync("org/repo-b");

        var dbNodeB = await AddNodeAsync(
            IntelligenceNodeType.Database,
            "db:db-b.example.com",
            "db-b.example.com");

        var serviceNodeB = await AddNodeAsync(
            IntelligenceNodeType.Service,
            $"service:{repoB.Id}:api-b",
            "api-b",
            repoB.Id);

        await AddEdgeAsync(repoNodeB.Id, dbNodeB.Id, IntelligenceEdgeType.RelatedTo);
        await AddEdgeAsync(serviceNodeB.Id, repoNodeB.Id, IntelligenceEdgeType.BelongsTo);

        // Analyze Repo A only
        await _engine.AnalyzeRepositoryGraphAsync(repoA.Id);

        var findings = await _dbContext.SecurityFindings.ToListAsync();

        // All findings must belong to Repo A
        Assert.All(findings, f => Assert.Equal(repoA.Id, f.RepositoryId));

        // No finding should reference Repo B entities
        var evidences = await _dbContext.SecurityFindingEvidences.ToListAsync();
        Assert.DoesNotContain(evidences, e => e.IntelligenceNodeId == dbNodeB.Id);
        Assert.DoesNotContain(evidences, e => e.IntelligenceNodeId == serviceNodeB.Id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 11: Finding Identity Stable Across Label Changes
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test11_FindingIdentity_StableAcrossLabelChanges()
    {
        var (repo, repoNode) = await SeedRepoWithGraphNodeAsync();

        var candNode = await AddNodeAsync(
            IntelligenceNodeType.CredentialCandidate,
            $"candidate:{Guid.NewGuid()}",
            "OpenAI (sk-****orig) [Valid]",
            repo.Id,
            JsonSerializer.Serialize(new
            {
                credentialType = "OpenAI",
                latestValidationStatus = "Valid",
                maskedValue = "sk-****orig"
            }));

        await AddEdgeAsync(candNode.Id, repoNode.Id, IntelligenceEdgeType.AppearsIn);

        // First analysis
        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);
        var firstCount = await _dbContext.SecurityFindings.CountAsync();
        var firstFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.FindingType == FindingType.ValidatedCredentialExposed);
        var firstFingerprint = firstFinding.FindingFingerprint;

        // Change the node's Label and Name (display change only)
        candNode.Label = "OpenAI (sk-****updated) [Valid]";
        candNode.MetadataJson = JsonSerializer.Serialize(new
        {
            credentialType = "OpenAI",
            latestValidationStatus = "Valid",
            maskedValue = "sk-****updated"
        });
        await _dbContext.SaveChangesAsync();

        // Second analysis — same Node.Id, different label
        await _engine.AnalyzeRepositoryGraphAsync(repo.Id);
        var secondCount = await _dbContext.SecurityFindings.CountAsync();

        // Finding count must not change — same finding updated, no duplicate
        Assert.Equal(firstCount, secondCount);

        // Same fingerprint (identity based on Node.Id, not Label)
        var updatedFinding = await _dbContext.SecurityFindings.FirstAsync(f => f.FindingType == FindingType.ValidatedCredentialExposed);
        Assert.Equal(firstFingerprint, updatedFinding.FindingFingerprint);
    }
}
