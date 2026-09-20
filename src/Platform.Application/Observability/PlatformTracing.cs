using System.Diagnostics;

namespace Platform.Application.Observability;

public static class PlatformTracing
{
    public const string ActivitySourceName = "APIHunter.SecurityPlatform";
    public const string ActivitySourceVersion = "1.0.0";

    public static readonly ActivitySource ActivitySource = new(ActivitySourceName, ActivitySourceVersion);

    public static Activity? StartJobExecutionActivity(string jobKind, Guid jobId, Guid? tenantId)
    {
        var activity = ActivitySource.StartActivity($"JobExecution.{jobKind}", ActivityKind.Internal);
        if (activity != null)
        {
            activity.SetTag("job.id", jobId.ToString());
            activity.SetTag("job.kind", jobKind);
            if (tenantId.HasValue)
            {
                activity.SetTag("tenant.id", tenantId.Value.ToString());
            }
        }
        return activity;
    }

    public static Activity? StartAiDiagnosisActivity(Guid incidentId, string provider)
    {
        var activity = ActivitySource.StartActivity("AiOperationalDiagnosis", ActivityKind.Client);
        if (activity != null)
        {
            activity.SetTag("incident.id", incidentId.ToString());
            activity.SetTag("ai.provider", provider);
        }
        return activity;
    }

    public static Activity? StartIncidentMitigationActivity(Guid incidentId, string category)
    {
        var activity = ActivitySource.StartActivity("IncidentMitigation", ActivityKind.Internal);
        if (activity != null)
        {
            activity.SetTag("incident.id", incidentId.ToString());
            activity.SetTag("incident.category", category);
        }
        return activity;
    }
}
