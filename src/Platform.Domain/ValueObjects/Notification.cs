namespace Platform.Domain.ValueObjects;

/// <summary>
/// Notification value object passed through the notification pipeline.
/// Application layer constructs this; providers consume it.
/// </summary>
public record Notification(
    string Subject,
    string Body,
    string RecipientEmail,
    string? RecipientName = null,
    bool IsHtml = true,
    Dictionary<string, string>? Metadata = null);
