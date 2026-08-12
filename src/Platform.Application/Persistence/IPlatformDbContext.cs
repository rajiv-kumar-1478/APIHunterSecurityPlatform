using Microsoft.EntityFrameworkCore;
using Platform.Domain.Entities;

namespace Platform.Application.Persistence;

/// <summary>
/// Application-layer abstraction for the platform database.
/// Infrastructure provides the EF Core implementation.
/// </summary>
public interface IPlatformDbContext
{
    DbSet<User> Users { get; }
    DbSet<AuthenticationSession> AuthenticationSessions { get; }
    DbSet<Permission> Permissions { get; }
    DbSet<UserPermission> UserPermissions { get; }
    DbSet<FieldPermission> FieldPermissions { get; }
    DbSet<AuditEvent> AuditEvents { get; }
    DbSet<NotificationProviderConfig> NotificationProviderConfigs { get; }
    DbSet<SystemSetting> SystemSettings { get; }

    DbSet<ApiHunterRecord> ApiHunterRecords { get; }
    DbSet<ApiHunterRepoReference> ApiHunterRepoReferences { get; }
    DbSet<ApiHunterSyncState> ApiHunterSyncStates { get; }

    DbSet<Repository> Repositories { get; }
    DbSet<RepositorySource> RepositorySources { get; }
    DbSet<RepositorySnapshot> RepositorySnapshots { get; }
    DbSet<SnapshotFile> SnapshotFiles { get; }
    DbSet<CredentialCandidate> CredentialCandidates { get; }
    DbSet<CandidateOccurrence> CandidateOccurrences { get; }
    DbSet<DetectionRule> DetectionRules { get; }
    DbSet<AnalysisJob> AnalysisJobs { get; }

    // Phase 4 DbSets
    DbSet<AiProviderConfig> AiProviderConfigs { get; }
    DbSet<AiInvestigationJob> AiInvestigationJobs { get; }
    DbSet<AiInvestigationCheckpoint> AiInvestigationCheckpoints { get; }
    DbSet<AiInvestigationEvidence> AiInvestigationEvidences { get; }
    DbSet<SecurityIntelligenceNode> SecurityIntelligenceNodes { get; }
    DbSet<SecurityIntelligenceEdge> SecurityIntelligenceEdges { get; }
    DbSet<RepositoryRiskScore> RepositoryRiskScores { get; }

    // Phase 5 DbSets
    DbSet<CredentialValidationResult> CredentialValidationResults { get; }

    // Phase 6 DbSets
    DbSet<SecurityFinding> SecurityFindings { get; }
    DbSet<SecurityFindingEvidence> SecurityFindingEvidences { get; }
    DbSet<SecurityFindingStatusHistory> SecurityFindingStatusHistories { get; }
    DbSet<SecurityAlertLog> SecurityAlertLogs { get; }


    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);

}


