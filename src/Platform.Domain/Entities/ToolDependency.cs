using System;

namespace Platform.Domain.Entities;

public class ToolDependency
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string ParentToolKey { get; set; } = string.Empty;

    public string DependencyToolKey { get; set; } = string.Empty;

    public string RequiredVersion { get; set; } = string.Empty;

    public string RequiredSha256 { get; set; } = string.Empty;

    public bool Required { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
