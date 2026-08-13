using System;

namespace Platform.Domain.Entities;

public class SecurityTarget
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = string.Empty;

    public string BaseUrl { get; set; } = string.Empty;

    public string TargetType { get; set; } = "Website";

    public bool Enabled { get; set; } = true;

    public bool MonitoringEnabled { get; set; } = false;

    public int ScanIntervalHours { get; set; } = 24;

    public DateTime? LastScanAtUtc { get; set; }

    public DateTime? NextScanAtUtc { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
