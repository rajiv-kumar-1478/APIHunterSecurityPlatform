using Platform.Domain.Enums;

namespace Platform.Domain.Contracts;

public interface IApiHunterStatusMapper
{
    PlatformKeyStatus MapStatus(int statusCode);
    string MapApiType(int apiTypeCode);
}
