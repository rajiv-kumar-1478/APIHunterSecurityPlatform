using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Platform.Application.Configuration;
using Platform.Infrastructure.Adapters.ObjectStore;
using Xunit;

namespace Platform.UnitTests;

public class ObjectStoreTests : IDisposable
{
    private readonly string _tempDir;

    public ObjectStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "apihunter_test_store_" + Guid.NewGuid());
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, true);
        }
    }

    [Fact]
    public void FileSystemObjectStore_ProductionEnvironment_ThrowsInvalidOperationException()
    {
        var envMock = new Mock<IHostEnvironment>();
        envMock.Setup(e => e.EnvironmentName).Returns("Production");

        var options = Options.Create(new ObjectStoreOptions
        {
            BasePath = _tempDir
        });

        Assert.Throws<InvalidOperationException>(() =>
            new FileSystemObjectStore(envMock.Object, options, NullLogger<FileSystemObjectStore>.Instance));
    }

    [Fact]
    public async Task FileSystemObjectStore_PutGetExistsDelete_RoundTrip()
    {
        var envMock = new Mock<IHostEnvironment>();
        envMock.Setup(e => e.EnvironmentName).Returns("Development");

        var options = Options.Create(new ObjectStoreOptions
        {
            BasePath = _tempDir
        });

        var store = new FileSystemObjectStore(envMock.Object, options, NullLogger<FileSystemObjectStore>.Instance);


        var key = "test/repo/file.txt";
        var contentString = "Hello APIHunter ObjectStore!";
        using var putStream = new MemoryStream(Encoding.UTF8.GetBytes(contentString));

        // Put
        var returnedKey = await store.PutAsync(key, putStream);
        Assert.Equal(key, returnedKey);

        // Exists
        var exists = await store.ExistsAsync(key);
        Assert.True(exists);

        // Get
        {
            await using var getStream = await store.GetAsync(key);
            using var reader = new StreamReader(getStream);
            var retrievedText = await reader.ReadToEndAsync();
            Assert.Equal(contentString, retrievedText);
        }

        // Delete
        await store.DeleteAsync(key);
        var existsAfterDelete = await store.ExistsAsync(key);
        Assert.False(existsAfterDelete);
    }


    [Fact]
    public async Task FileSystemObjectStore_PathTraversalKey_RejectsAttempt()
    {
        var envMock = new Mock<IHostEnvironment>();
        envMock.Setup(e => e.EnvironmentName).Returns("Development");

        var options = Options.Create(new ObjectStoreOptions
        {
            BasePath = _tempDir
        });

        var store = new FileSystemObjectStore(envMock.Object, options, NullLogger<FileSystemObjectStore>.Instance);


        var traversalKey = "../../../etc/passwd";
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("test"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.PutAsync(traversalKey, stream));
    }
}
