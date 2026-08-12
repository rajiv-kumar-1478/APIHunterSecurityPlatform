using FluentAssertions;
using Platform.Domain.Enums;
using Platform.Infrastructure.Adapters.ApiHunter;
using Xunit;

namespace Platform.UnitTests;

public class ApiHunterAdapterUnitTests
{
    private readonly ApiHunterStatusMapper _mapper = new();

    [Theory]
    [InlineData(1, PlatformKeyStatus.Valid)]
    [InlineData(7, PlatformKeyStatus.ValidNoCredits)]
    [InlineData(0, PlatformKeyStatus.Invalid)]
    [InlineData(-99, PlatformKeyStatus.Unverified)]
    [InlineData(6, PlatformKeyStatus.Error)]
    [InlineData(-1, PlatformKeyStatus.Unknown)]
    [InlineData(42, PlatformKeyStatus.Unknown)]
    [InlineData(500, PlatformKeyStatus.Unknown)]
    [InlineData(999, PlatformKeyStatus.Unknown)]
    [InlineData(1000, PlatformKeyStatus.Unknown)]
    public void MapStatus_MapsApiHunterStatusToPlatformDomainStatus(int apiHunterStatus, PlatformKeyStatus expected)
    {
        // Act
        var result = _mapper.MapStatus(apiHunterStatus);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData(100, "OpenAI")]
    [InlineData(120, "AnthropicClaude")]
    [InlineData(198, "DeepSeek")]
    [InlineData(250, "Groq")]
    [InlineData(330, "AWSIAM")]
    [InlineData(410, "SendGrid")]
    [InlineData(425, "Mailgun")]
    public void MapApiType_MapsKnownApiTypeCodesToStringNames(int apiTypeCode, string expectedName)
    {
        // Act
        var result = _mapper.MapApiType(apiTypeCode);

        // Assert
        result.Should().Be(expectedName);
    }
}
