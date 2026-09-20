namespace Platform.Application.Operations;

public interface IOperationalPromptSanitizer
{
    string Sanitize(string? rawText);
}
