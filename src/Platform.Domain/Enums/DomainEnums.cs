namespace Platform.Domain.Enums;

public enum NotificationChannel
{
    Email,
    Telegram
}

public enum NotificationProviderType
{
    Smtp,
    SendGrid,
    Mailgun,
    TelegramBot
}

public enum AuditEventCode
{
    // Auth
    UserLogin,
    UserLoginFailed,
    UserLogout,
    UserLocked,
    SessionRevoked,

    // User management
    UserCreated,
    UserUpdated,
    UserDisabled,
    UserEnabled,
    PasswordChanged,

    // Permissions
    PermissionGranted,
    PermissionRevoked,
    FieldPermissionChanged,

    // Authorization failures
    AccessDenied,
    FieldAccessDenied,

    // Settings
    SystemSettingChanged,
    NotificationProviderChanged,

    // Notifications
    NotificationSent,
    NotificationFailed,
    NotificationTestSent
}

public enum FieldAction
{
    Read,
    Write
}

public enum SettingValueType
{
    String,
    Integer,
    Boolean,
    Json
}
