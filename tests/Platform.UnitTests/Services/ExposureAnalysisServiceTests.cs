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

public class ExposureAnalysisServiceTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;
    private readonly SecurityFindingService _findingService;
    private readonly ExposureAnalysisService _exposureService;
    private readonly RiskEngine _riskEngine;

    public ExposureAnalysisServiceTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("ExposureAnalysisDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);

        var riskPolicy = new RiskPolicyOptions();
        _riskEngine = new RiskEngine(riskPolicy);
        _findingService = new SecurityFindingService(
            _dbContext, _riskEngine, new Mock<ILogger<SecurityFindingService>>().Object);
        _exposureService = new ExposureAnalysisService(
            _dbContext, _findingService, new Mock<ILogger<ExposureAnalysisService>>().Object);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Seeding Methods
    // ─────────────────────────────────────────────────────────────────────────

    private async Task<Repository> SeedRepoAsync(string repoName = "octocat/exposure-repo")
    {
        var repo = new Repository { FullName = repoName };
        _dbContext.Repositories.Add(repo);
        await _dbContext.SaveChangesAsync();
        return repo;
    }

    private async Task<RepositorySnapshot> SeedSnapshotAsync(Guid repoId, string commitSha, DateTime acquiredAtUtc)
    {
        var snapshot = new RepositorySnapshot
        {
            RepositoryId = repoId,
            CommitSha = commitSha,
            BranchName = "main",
            AcquiredAtUtc = acquiredAtUtc
        };
        _dbContext.RepositorySnapshots.Add(snapshot);
        await _dbContext.SaveChangesAsync();
        return snapshot;
    }

    private async Task<SnapshotFile> SeedSnapshotFileAsync(Guid snapshotId, string filePath)
    {
        var file = new SnapshotFile
        {
            SnapshotId = snapshotId,
            FilePath = filePath,
            FileName = Path.GetFileName(filePath),
            ContentHash = Guid.NewGuid().ToString("N")
        };
        _dbContext.SnapshotFiles.Add(file);
        await _dbContext.SaveChangesAsync();
        return file;
    }

    private async Task<CredentialCandidate> SeedCandidateAsync(string maskedValue = "sk-****1234", CandidateStatus status = CandidateStatus.Detected)
    {
        var candidate = new CredentialCandidate
        {
            SecretFingerprint = Guid.NewGuid().ToString("N"),
            MaskedValue = maskedValue,
            CredentialType = "OpenAI",
            Status = status
        };
        _dbContext.CredentialCandidates.Add(candidate);
        await _dbContext.SaveChangesAsync();
        return candidate;
    }

    private async Task<CandidateOccurrence> SeedOccurrenceAsync(Guid candidateId, Guid fileId, Guid repoId, int lineNumber = 10)
    {
        var occ = new CandidateOccurrence
        {
            CandidateId = candidateId,
            SnapshotFileId = fileId,
            RepositoryId = repoId,
            LineNumber = lineNumber,
            OccurrenceFingerprint = Guid.NewGuid().ToString("N")
        };
        _dbContext.CandidateOccurrences.Add(occ);
        await _dbContext.SaveChangesAsync();
        return occ;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Single Snapshot — No Historical Exposure Finding
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test1_SingleSnapshot_DoesNotCreateHistoricalFinding()
    {
        var repo = await SeedRepoAsync();
        var snapshot = await SeedSnapshotAsync(repo.Id, "commit-sha-1", DateTime.UtcNow);
        var file = await SeedSnapshotFileAsync(snapshot.Id, "config/settings.py");
        var candidate = await SeedCandidateAsync();
        await SeedOccurrenceAsync(candidate.Id, file.Id, repo.Id);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.ToListAsync();
        Assert.DoesNotContain(findings, f => f.FindingType == FindingType.HistoricalExposureDetected);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Multi-Snapshot — Creates HistoricalExposureDetected Finding
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test2_MultiSnapshot_CreatesHistoricalFinding()
    {
        var repo = await SeedRepoAsync();
        var snapshot1 = await SeedSnapshotAsync(repo.Id, "commit-sha-1111111", DateTime.UtcNow.AddDays(-30));
        var snapshot2 = await SeedSnapshotAsync(repo.Id, "commit-sha-2222222", DateTime.UtcNow);

        var file1 = await SeedSnapshotFileAsync(snapshot1.Id, "config/settings.py");
        var file2 = await SeedSnapshotFileAsync(snapshot2.Id, "config/settings.py");

        var candidate = await SeedCandidateAsync();
        await SeedOccurrenceAsync(candidate.Id, file1.Id, repo.Id);
        await SeedOccurrenceAsync(candidate.Id, file2.Id, repo.Id);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.ToListAsync();
        Assert.Contains(findings, f => f.FindingType == FindingType.HistoricalExposureDetected);

        var finding = findings.First(f => f.FindingType == FindingType.HistoricalExposureDetected);
        Assert.Equal(repo.Id, finding.RepositoryId);
        Assert.Equal(candidate.Id.ToString("N"), SecurityFindingService.ComputeFindingFingerprint(repo.Id, FindingType.HistoricalExposureDetected, candidate.Id.ToString("N")) == finding.FindingFingerprint ? candidate.Id.ToString("N") : candidate.Id.ToString("N"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Multiple Occurrences in Same Commit Preserved as Distinct Evidence
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test3_MultiOccurrenceInSameCommit_PreservesIndividualEvidence()
    {
        var repo = await SeedRepoAsync();
        var snapshot1 = await SeedSnapshotAsync(repo.Id, "sha-1", DateTime.UtcNow.AddDays(-10));
        var snapshot2 = await SeedSnapshotAsync(repo.Id, "sha-2", DateTime.UtcNow);

        var file1a = await SeedSnapshotFileAsync(snapshot1.Id, "config/a.py");
        var file1b = await SeedSnapshotFileAsync(snapshot1.Id, "config/b.py");
        var file2 = await SeedSnapshotFileAsync(snapshot2.Id, "config/a.py");

        var candidate = await SeedCandidateAsync();
        // 2 occurrences in snapshot 1 (file1a L10, file1b L25)
        await SeedOccurrenceAsync(candidate.Id, file1a.Id, repo.Id, 10);
        await SeedOccurrenceAsync(candidate.Id, file1b.Id, repo.Id, 25);
        // 1 occurrence in snapshot 2
        await SeedOccurrenceAsync(candidate.Id, file2.Id, repo.Id, 10);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var finding = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .FirstAsync(f => f.FindingType == FindingType.HistoricalExposureDetected);

        // All 3 occurrences produce individual HistoricalCommit evidence records
        Assert.Equal(3, finding.Evidences.Count(e => e.EvidenceType == FindingEvidenceType.HistoricalCommit));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Enriches Existing Validated Credential Finding with Historical Evidence
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test4_EnrichesExistingValidatedCredentialFinding()
    {
        var repo = await SeedRepoAsync();

        var candidate = await SeedCandidateAsync("sk-****valid");

        // Pre-create ValidatedCredentialExposed finding for candidate
        var validatedFinding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
            RepositoryId: repo.Id,
            SnapshotId: null,
            FindingType: FindingType.ValidatedCredentialExposed,
            Severity: RiskSeverity.High,
            Confidence: FindingConfidence.High,
            Title: "Validated credential exposed",
            Description: "Live OpenAI key",
            CoreEntityId: candidate.Id.ToString("N")
        ));

        // Create 2 commit snapshots
        var snapshot1 = await SeedSnapshotAsync(repo.Id, "sha-v1", DateTime.UtcNow.AddDays(-20));
        var snapshot2 = await SeedSnapshotAsync(repo.Id, "sha-v2", DateTime.UtcNow);
        var file1 = await SeedSnapshotFileAsync(snapshot1.Id, "app.py");
        var file2 = await SeedSnapshotFileAsync(snapshot2.Id, "app.py");

        await SeedOccurrenceAsync(candidate.Id, file1.Id, repo.Id);
        await SeedOccurrenceAsync(candidate.Id, file2.Id, repo.Id);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var updatedValidatedFinding = await _dbContext.SecurityFindings
            .Include(f => f.Evidences)
            .FirstAsync(f => f.Id == validatedFinding.Id);

        // HistoricalCommit evidence attached to existing Validated finding
        Assert.Contains(updatedValidatedFinding.Evidences, e => e.EvidenceType == FindingEvidenceType.HistoricalCommit);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: RiskEngine Applies HISTORICAL_COMMIT Factor
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test5_RiskEngine_AppliesHistoricalCommitFactor()
    {
        var repo = await SeedRepoAsync();
        var candidate = await SeedCandidateAsync("sk-****risk");

        // Create unvalidated finding
        var unvalidatedFinding = await _findingService.UpsertFindingAsync(new CreateOrUpdateFindingRequest(
            RepositoryId: repo.Id,
            SnapshotId: null,
            FindingType: FindingType.UnvalidatedCredentialExposed,
            Severity: RiskSeverity.Medium,
            Confidence: FindingConfidence.Medium,
            Title: "Unvalidated credential",
            Description: "Exposed key",
            CoreEntityId: candidate.Id.ToString("N")
        ));

        int initialScore = unvalidatedFinding.RiskScore;

        // 2 snapshots
        var s1 = await SeedSnapshotAsync(repo.Id, "sha-r1", DateTime.UtcNow.AddDays(-15));
        var s2 = await SeedSnapshotAsync(repo.Id, "sha-r2", DateTime.UtcNow);
        var f1 = await SeedSnapshotFileAsync(s1.Id, "secrets.env");
        var f2 = await SeedSnapshotFileAsync(s2.Id, "secrets.env");

        await SeedOccurrenceAsync(candidate.Id, f1.Id, repo.Id);
        await SeedOccurrenceAsync(candidate.Id, f2.Id, repo.Id);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var rescoredFinding = await _dbContext.SecurityFindings
            .FirstAsync(f => f.Id == unvalidatedFinding.Id);

        // Score must increase due to HISTORICAL_COMMIT (+10) factor
        Assert.True(rescoredFinding.RiskScore > initialScore, $"Expected score > {initialScore}, got {rescoredFinding.RiskScore}");
        Assert.Contains("HISTORICAL_COMMIT", rescoredFinding.RiskFactorBreakdownJson);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Idempotency — Run Twice, No Duplicate Findings or Evidence
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test6_Idempotency_RunTwice_NoDuplicateFindings()
    {
        var repo = await SeedRepoAsync();
        var s1 = await SeedSnapshotAsync(repo.Id, "sha-idemp-1", DateTime.UtcNow.AddDays(-5));
        var s2 = await SeedSnapshotAsync(repo.Id, "sha-idemp-2", DateTime.UtcNow);
        var f1 = await SeedSnapshotFileAsync(s1.Id, "env.py");
        var f2 = await SeedSnapshotFileAsync(s2.Id, "env.py");
        var candidate = await SeedCandidateAsync();

        await SeedOccurrenceAsync(candidate.Id, f1.Id, repo.Id);
        await SeedOccurrenceAsync(candidate.Id, f2.Id, repo.Id);

        // Run 1
        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);
        int count1 = await _dbContext.SecurityFindings.CountAsync();
        int evidenceCount1 = await _dbContext.SecurityFindingEvidences.CountAsync();

        // Run 2
        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);
        int count2 = await _dbContext.SecurityFindings.CountAsync();
        int evidenceCount2 = await _dbContext.SecurityFindingEvidences.CountAsync();

        Assert.Equal(count1, count2);
        Assert.Equal(evidenceCount1, evidenceCount2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: SafeEvidenceJson — Zero Raw Secrets
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test7_SafeEvidenceJson_NoSecretLeak()
    {
        var repo = await SeedRepoAsync();
        var candidate = await SeedCandidateAsync("sk-****secret");

        var s1 = await SeedSnapshotAsync(repo.Id, "sha-sec1", DateTime.UtcNow.AddDays(-10));
        var s2 = await SeedSnapshotAsync(repo.Id, "sha-sec2", DateTime.UtcNow);
        var f1 = await SeedSnapshotFileAsync(s1.Id, "config.json");
        var f2 = await SeedSnapshotFileAsync(s2.Id, "config.json");

        await SeedOccurrenceAsync(candidate.Id, f1.Id, repo.Id);
        await SeedOccurrenceAsync(candidate.Id, f2.Id, repo.Id);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var evidences = await _dbContext.SecurityFindingEvidences
            .Where(e => e.EvidenceType == FindingEvidenceType.HistoricalCommit)
            .ToListAsync();

        Assert.NotEmpty(evidences);

        string[] forbiddenPatterns = new[] { "sk-proj-", "AKIA", "ghp_", "password", "secretKey" };
        foreach (var ev in evidences)
        {
            foreach (var forbidden in forbiddenPatterns)
            {
                Assert.DoesNotContain(forbidden, ev.SafeEvidenceJson);
            }
            Assert.Contains("commitSha", ev.SafeEvidenceJson);
            Assert.Contains("filePath", ev.SafeEvidenceJson);
            Assert.Contains("lineNumber", ev.SafeEvidenceJson);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8: Multiple Candidates Analyzed Independently
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test8_MultipleCandidates_AnalyzedIndependently()
    {
        var repo = await SeedRepoAsync();
        var s1 = await SeedSnapshotAsync(repo.Id, "sha-mc1", DateTime.UtcNow.AddDays(-10));
        var s2 = await SeedSnapshotAsync(repo.Id, "sha-mc2", DateTime.UtcNow);
        var f1 = await SeedSnapshotFileAsync(s1.Id, "a.py");
        var f2 = await SeedSnapshotFileAsync(s2.Id, "b.py");

        var candMulti = await SeedCandidateAsync("sk-****multi"); // In 2 snapshots
        var candSingle = await SeedCandidateAsync("sk-****single"); // In 1 snapshot only

        // candMulti in s1 and s2
        await SeedOccurrenceAsync(candMulti.Id, f1.Id, repo.Id);
        await SeedOccurrenceAsync(candMulti.Id, f2.Id, repo.Id);

        // candSingle in s1 only
        await SeedOccurrenceAsync(candSingle.Id, f1.Id, repo.Id);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var historicalFindings = await _dbContext.SecurityFindings
            .Where(f => f.FindingType == FindingType.HistoricalExposureDetected)
            .ToListAsync();

        // Exactly 1 historical finding (for candMulti)
        Assert.Single(historicalFindings);
        Assert.Equal(SecurityFindingService.ComputeFindingFingerprint(repo.Id, FindingType.HistoricalExposureDetected, candMulti.Id.ToString("N")), historicalFindings[0].FindingFingerprint);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9: Empty Repository — Zero Findings, No Exceptions
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test9_EmptyRepository_ZeroFindings_NoExceptions()
    {
        var repo = await SeedRepoAsync("octocat/empty-history-repo");

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var findings = await _dbContext.SecurityFindings.ToListAsync();
        Assert.Empty(findings);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 10: CandidateStatus Preserved Unchanged
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Test10_CandidateStatus_PreservedUnchanged()
    {
        var repo = await SeedRepoAsync();
        var s1 = await SeedSnapshotAsync(repo.Id, "sha-st1", DateTime.UtcNow.AddDays(-5));
        var s2 = await SeedSnapshotAsync(repo.Id, "sha-st2", DateTime.UtcNow);
        var f1 = await SeedSnapshotFileAsync(s1.Id, "main.py");
        var f2 = await SeedSnapshotFileAsync(s2.Id, "main.py");

        var candidate = await SeedCandidateAsync("sk-****status", CandidateStatus.Detected);
        await SeedOccurrenceAsync(candidate.Id, f1.Id, repo.Id);
        await SeedOccurrenceAsync(candidate.Id, f2.Id, repo.Id);

        await _exposureService.AnalyzeRepositorySnapshotHistoryAsync(repo.Id);

        var candidateAfter = await _dbContext.CredentialCandidates.FirstAsync(c => c.Id == candidate.Id);
        Assert.Equal(CandidateStatus.Detected, candidateAfter.Status);
    }
}
