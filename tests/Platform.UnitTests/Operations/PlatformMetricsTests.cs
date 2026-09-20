using FluentAssertions;
using Platform.Application.Observability;
using Xunit;

namespace Platform.UnitTests.Operations;

public class PlatformMetricsTests
{
    [Fact]
    public void PlatformMetrics_GaugesUpdateCorrectly()
    {
        PlatformMetrics.SetActiveWorkers(7);
        PlatformMetrics.SetPendingQueueDepth(55);
        PlatformMetrics.SetOverdueCampaigns(4);

        PlatformMetrics.CurrentActiveWorkers.Should().Be(7);
        PlatformMetrics.CurrentPendingQueueDepth.Should().Be(55);
        PlatformMetrics.CurrentOverdueCampaigns.Should().Be(4);
    }

    [Fact]
    public void PlatformMetrics_MeterIdentity_IsConsistent()
    {
        PlatformMetrics.MeterName.Should().Be("APIHunter.SecurityPlatform");
        PlatformMetrics.MeterVersion.Should().Be("1.0.0");
        PlatformTracing.ActivitySourceName.Should().Be("APIHunter.SecurityPlatform");
    }
}
