using Microsoft.EntityFrameworkCore;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests.Persistence;

public class Phase5DatabaseMappingTests : IDisposable
{
    private readonly PlatformDbContext _dbContext;

    public Phase5DatabaseMappingTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase("Phase5DbMappingTestDb_" + Guid.NewGuid())
            .Options;
        _dbContext = new PlatformDbContext(options);
    }

    public void Dispose()
    {
        _dbContext.Database.EnsureDeleted();
        _dbContext.Dispose();
    }

    [Fact]
    public async Task CredentialValidationResult_MappingAndIndexes_Succeeds()
    {
        var candidate = new CredentialCandidate
        {
            CredentialType = "GitHub",
            MaskedValue = "ghp_****1234",
            Status = CandidateStatus.Triaged
        };

        var job = new AnalysisJob
        {
            JobType = JobType.CredentialValidation,
            Status = JobStatus.Succeeded,
            TargetEntityType = "Candidate",
            TargetEntityId = candidate.Id
        };

        _dbContext.CredentialCandidates.Add(candidate);
        _dbContext.AnalysisJobs.Add(job);
        await _dbContext.SaveChangesAsync();

        var valResult = new CredentialValidationResult
        {
            CandidateId = candidate.Id,
            AnalysisJobId = job.Id,
            ProviderName = "GitHub",
            Status = ValidationStatus.Valid,
            Confidence = ValidationConfidence.Confirmed,
            ValidatorVersion = "1.0.0",
            PolicyVersion = "1.0.0",
            ResponseClassification = "HTTP 200 OK - User Authenticated",
            SafeEvidenceJson = "{\"username\":\"octocat\"}",
            LatencyMs = 145,
            HttpStatusCode = 200
        };

        _dbContext.CredentialValidationResults.Add(valResult);
        await _dbContext.SaveChangesAsync();

        var fetched = await _dbContext.CredentialValidationResults
            .Include(r => r.Candidate)
            .Include(r => r.AnalysisJob)
            .FirstOrDefaultAsync(r => r.Id == valResult.Id);

        Assert.NotNull(fetched);
        Assert.Equal("GitHub", fetched.ProviderName);
        Assert.Equal(ValidationStatus.Valid, fetched.Status);
        Assert.Equal(ValidationConfidence.Confirmed, fetched.Confidence);
        Assert.Equal(candidate.Id, fetched.Candidate.Id);
        Assert.Equal(job.Id, fetched.AnalysisJob!.Id);
        Assert.Equal(JobType.CredentialValidation, fetched.AnalysisJob.JobType);
    }
}
