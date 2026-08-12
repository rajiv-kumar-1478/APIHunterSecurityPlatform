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
    NotificationTestSent,

    // APIHunter Integration
    ApiHunterSyncStarted,
    ApiHunterSyncCompleted,
    ApiHunterSyncFailed,
    CredentialRevealed
}

public enum PlatformKeyStatus
{
    Unverified = -99,
    Invalid = 0,
    Valid = 1,
    Error = 6,
    ValidNoCredits = 7,
    Unknown = 99
}

public enum SyncStatus
{
    Idle,
    InProgress,
    Completed,
    Failed
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
