using FluentAssertions;
using Xunit;

namespace Platform.UnitTests.Scanning;

public sealed class ProductionTopologyContractTests
{
    [Fact]
    public void Compose_DeclaresDeployableApiWorkerAndFrontendWithoutWorkerDockerAccess()
    {
        var root = FindRepositoryRoot();
        var composePath = Path.Combine(root, "docker-compose.yml");
        var workerDockerfile = Path.Combine(root, "deployment", "docker", "Dockerfile.worker");
        var frontendDockerfile = Path.Combine(root, "frontend", "dashboard", "Dockerfile");

        File.Exists(composePath).Should().BeTrue();
        File.Exists(workerDockerfile).Should().BeTrue();
        File.Exists(frontendDockerfile).Should().BeTrue();

        var compose = File.ReadAllText(composePath);
        compose.Should().Contain("  worker:");
        compose.Should().Contain("dockerfile: deployment/docker/Dockerfile.worker");
        compose.Should().Contain("dockerfile: Dockerfile");
        compose.Should().Contain("ScannerRuntime__RuntimeMode: Disabled");
        compose.Should().Contain("ScanJobConsumer__Enabled: \"false\"");
        compose.Should().Contain("CampaignScheduler__GlobalEnabled: \"false\"");
        compose.Should().Contain("internal: true");
        compose.Should().NotContain("/var/run/docker.sock");
        compose.Should().NotContain("privileged: true");
        compose.Should().NotContain("scanner-service:latest");
        compose.Should().NotContain("egress-gateway:latest");
    }

    [Fact]
    public void ContainerDefinitions_RunApplicationProcessesAsNonRootUsers()
    {
        var root = FindRepositoryRoot();
        var api = File.ReadAllText(Path.Combine(root, "deployment", "docker", "Dockerfile.api"));
        var worker = File.ReadAllText(Path.Combine(root, "deployment", "docker", "Dockerfile.worker"));
        var frontend = File.ReadAllText(Path.Combine(root, "frontend", "dashboard", "Dockerfile"));

        api.Should().Contain("USER $APP_UID");
        worker.Should().Contain("USER $APP_UID");
        frontend.Should().Contain("USER nextjs");
        frontend.Should().Contain("/app/.next/standalone");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "docker-compose.yml")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root from the test output directory.");
    }
}
