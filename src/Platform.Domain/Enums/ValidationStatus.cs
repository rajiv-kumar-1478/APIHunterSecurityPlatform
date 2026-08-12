namespace Platform.Domain.Enums;

public enum ValidationStatus
{
    Unknown = 0,
    Pending = 1,
    Valid = 2,
    ValidInsufficientScope = 3,
    Invalid = 4,
    Expired = 5,
    Revoked = 6,
    RateLimited = 7,
    Unavailable = 8,
    Unsupported = 9,
    BlockedByPolicy = 10,
    ValidationError = 11
}
