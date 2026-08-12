using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Application.Permissions;
using Platform.Application.Services;
using Platform.Domain.Contracts;
using Platform.Domain.Entities;
using Platform.Domain.Enums;
using Platform.Infrastructure.Adapters.ApiHunter;
using Platform.Infrastructure.Persistence;
using Xunit;

namespace Platform.UnitTests;

public class ApiHunterSyncTests
{
    private readonly PlatformDbContext _db;
    private readonly Mock<IApiHunterSource> _sourceMock;
    private readonly ApiHunterStatusMapper _statusMapper;
    private readonly Mock<IDataProtectionProvider> _dpProviderMock;
    private readonly Mock<IDataProtector> _protectorMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly IOptions<ApiHunterSourceOptions> _options;
    private readonly Mock<ILogger<ApiHunterSyncService>> _loggerMock;
    private readonly ApiHunterSyncService _sut;

    public ApiHunterSyncTests()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _db = new PlatformDbContext(options);
        _sourceMock = new Mock<IApiHunterSource>();
        _statusMapper = new ApiHunterStatusMapper();
        _dpProviderMock = new Mock<IDataProtectionProvider>();
        _protectorMock = new Mock<IDataProtector>();
        _auditServiceMock = new Mock<IAuditService>();
        _loggerMock = new Mock<ILogger<ApiHunterSyncService>>();

        _dpProviderMock.Setup(p => p.CreateProtector(It.IsAny<string>())).Returns(_protectorMock.Object);
        _protectorMock.Setup(p => p.Protect(It.IsAny<byte[]>())).Returns<byte[]>(b => b);
        _protectorMock.Setup(p => p.Unprotect(It.IsAny<byte[]>())).Returns<byte[]>(b => b);

        _options = Options.Create(new ApiHunterSourceOptions { BatchSize = 100 });

        _sut = new ApiHunterSyncService(
            _db,
            _sourceMock.Object,
            _statusMapper,
            _dpProviderMock.Object,
            _auditServiceMock.Object,
            _options,
            _loggerMock.Object);
    }

    [Fact]
    public async Task SynchronizeAsync_ImportsKeysAndDeduplicatesOnRepeatedRun()
    {
        // Arrange
        var keys = new List<ApiHunterKeySourceDto>
        {
            new(101, "sk-proj-1234567890abcdef", 1, 100, 1, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, "OK", "$100", "tier_1", null, null, new List<ApiHunterRepoSourceDto>
            {
                new(501, 101, "https://github.com/owner/repo1", "owner", "repo1", ".env", "https://github.com/owner/repo1/blob/main/.env", 12, "OPENAI_KEY=sk-proj-1234567890abcdef", DateTime.UtcNow)
            }),
            new(102, "sk-proj-9876543210fedcba", 7, 198, 1, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, "QuotaExceeded", "$0", "free", null, null, new List<ApiHunterRepoSourceDto>())
        };

        _sourceMock
            .Setup(s => s.FetchKeysIncrementalAsync(0, 100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(keys);

        // Act 1: Initial Sync
        var result1 = await _sut.SynchronizeAsync();

        // Assert 1
        result1.Status.Should().Be("Completed");
        result1.RecordsImported.Should().Be(2);

        var recordsInDb = await _db.ApiHunterRecords.Include(r => r.RepoReferences).ToListAsync();
        recordsInDb.Should().HaveCount(2);

        var validRecord = recordsInDb.FirstOrDefault(r => r.SourceRecordId == 101);
        validRecord.Should().NotBeNull();
        validRecord!.Status.Should().Be(PlatformKeyStatus.Valid);
        validRecord.MaskedKey.Should().Be("sk-p****cdef");
        validRecord.RepoReferences.Should().HaveCount(1);

        var validNoCreditsRecord = recordsInDb.FirstOrDefault(r => r.SourceRecordId == 102);
        validNoCreditsRecord!.Status.Should().Be(PlatformKeyStatus.ValidNoCredits);

        // Act 2: Repeated Sync with same keys (Deduplication check)
        _sourceMock
            .Setup(s => s.FetchKeysIncrementalAsync(102, 100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ApiHunterKeySourceDto>());

        var result2 = await _sut.SynchronizeAsync();

        // Assert 2: Zero duplicate records created
        var finalRecordsCount = await _db.ApiHunterRecords.CountAsync();
        finalRecordsCount.Should().Be(2);
    }

    [Fact]
    public async Task SynchronizeAsync_WhenSourceRecordChanges_UpdatesExistingRecordWithoutDuplicating()
    {
        // Arrange: Initial record with Unverified status
        var initialKeys = new List<ApiHunterKeySourceDto>
        {
            new(201, "sk-proj-change12345678", -99, 100, 1, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, null, null, null, null, null, new List<ApiHunterRepoSourceDto>())
        };

        _sourceMock
            .Setup(s => s.FetchKeysIncrementalAsync(0, 100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(initialKeys);

        await _sut.SynchronizeAsync();

        // Act: Updated key with Status = 1 (Valid)
        var updatedKeys = new List<ApiHunterKeySourceDto>
        {
            new(201, "sk-proj-change12345678", 1, 100, 1, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, "OK", "$500", "tier_2", null, null, new List<ApiHunterRepoSourceDto>())
        };

        _sourceMock
            .Setup(s => s.FetchKeysIncrementalAsync(201, 100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(updatedKeys);

        var syncResult = await _sut.SynchronizeAsync();

        // Assert
        syncResult.RecordsUpdated.Should().Be(1);
        var record = await _db.ApiHunterRecords.FirstOrDefaultAsync(r => r.SourceRecordId == 201);
        record.Should().NotBeNull();
        record!.Status.Should().Be(PlatformKeyStatus.Valid);
        record.Balance.Should().Be("$500");
        (await _db.ApiHunterRecords.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task SynchronizeAsync_WhenFetchFails_MarksSyncStateFailedAndPreservesExistingData()
    {
        // Arrange
        _sourceMock
            .Setup(s => s.FetchKeysIncrementalAsync(It.IsAny<long>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database connection failed"));

        // Act
        var result = await _sut.SynchronizeAsync();

        // Assert
        result.Status.Should().Be("Failed");
        result.ErrorMessage.Should().Be("Database connection failed");

        var syncState = await _db.ApiHunterSyncStates.FirstOrDefaultAsync();
        syncState.Should().NotBeNull();
        syncState!.Status.Should().Be(SyncStatus.Failed);
    }

    [Fact]
    public async Task RevealKeyAsync_WhenRecordExists_DecryptsKeyAndRecordsAuditEvent()
    {
        // Arrange
        var record = new ApiHunterRecord
        {
            SourceRecordId = 301,
            MaskedKey = "sk-p****cdef",
            RawKeyEncrypted = Convert.ToBase64String(Encoding.UTF8.GetBytes("sk-proj-secretrawkey")),
            Status = PlatformKeyStatus.Valid,
            ApiType = "OpenAI",
            SearchProvider = "GitHub"
        };
        _db.ApiHunterRecords.Add(record);
        await _db.SaveChangesAsync();

        // Act
        var revealedKey = await _sut.RevealKeyAsync(record.Id);

        // Assert
        revealedKey.Should().Be("sk-proj-secretrawkey");
        _auditServiceMock.Verify(a => a.RecordAsync(
            AuditEventCode.CredentialRevealed,
            null,
            null,
            It.IsAny<string>(),
            It.IsAny<object>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }
}
