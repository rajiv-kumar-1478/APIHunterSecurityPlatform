using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Admin-controlled global configuration switches.
/// Secret values are masked in API responses.
/// </summary>
public class SystemSetting
{
    public string Key { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public SettingValueType ValueType { get; set; } = SettingValueType.String;
    public bool IsSecret { get; set; }
    public string Description { get; set; } = string.Empty;
    public Guid? UpdatedByUserId { get; set; }
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
