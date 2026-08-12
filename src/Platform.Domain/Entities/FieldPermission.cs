using Platform.Domain.Enums;

namespace Platform.Domain.Entities;

/// <summary>
/// Field-level authorization rule with ALLOW/DENY effect.
/// 
/// Authorization pipeline:
///   Authentication → Resource Auth → Permission Auth → Field Auth → DTO Projection → Response
/// 
/// Field permissions are NEVER the only protection. They supplement resource-level auth.
/// </summary>
public class FieldPermission
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Permission code that must be present for this field rule to apply.
    /// </summary>
    public string PermissionCode { get; set; } = string.Empty;

    /// <summary>
    /// The resource type this rule applies to. E.g. "ApiKey", "Credential"
    /// </summary>
    public string ResourceType { get; set; } = string.Empty;

    /// <summary>
    /// The field name. E.g. "RawValue", "SecretKey"
    /// </summary>
    public string FieldName { get; set; } = string.Empty;

    public FieldAction Action { get; set; } = FieldAction.Read;

    /// <summary>
    /// Allow = user CAN access this field if permission is present.
    /// Deny  = user CANNOT access this field even if permission is present (explicit override).
    /// </summary>
    public PermissionEffect Effect { get; set; } = PermissionEffect.Allow;

    // Navigation
    public Permission Permission { get; set; } = null!;
}
