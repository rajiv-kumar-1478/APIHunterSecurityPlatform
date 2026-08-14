using Microsoft.EntityFrameworkCore;
using Platform.Application.Persistence;
using Platform.Domain.Entities;
using Platform.Domain.Enums;

namespace Platform.Infrastructure.Persistence;

public class PlatformDbContext(DbContextOptions<PlatformDbContext> options)
    : DbContext(options), IPlatformDbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<AuthenticationSession> AuthenticationSessions => Set<AuthenticationSession>();
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<UserPermission> UserPermissions => Set<UserPermission>();
    public DbSet<FieldPermission> FieldPermissions => Set<FieldPermission>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<NotificationProviderConfig> NotificationProviderConfigs => Set<NotificationProviderConfig>();
    public DbSet<SystemSetting> SystemSettings => Set<SystemSetting>();
    public DbSet<ApiHunterRecord> ApiHunterRecords => Set<ApiHunterRecord>();
    public DbSet<ApiHunterRepoReference> ApiHunterRepoReferences => Set<ApiHunterRepoReference>();
    public DbSet<ApiHunterSyncState> ApiHunterSyncStates => Set<ApiHunterSyncState>();

    // Phase 3 DbSets
    public DbSet<Repository> Repositories => Set<Repository>();
    public DbSet<RepositorySource> RepositorySources => Set<RepositorySource>();
    public DbSet<RepositorySnapshot> RepositorySnapshots => Set<RepositorySnapshot>();
    public DbSet<SnapshotFile> SnapshotFiles => Set<SnapshotFile>();
    public DbSet<CredentialCandidate> CredentialCandidates => Set<CredentialCandidate>();
    public DbSet<CandidateOccurrence> CandidateOccurrences => Set<CandidateOccurrence>();
    public DbSet<DetectionRule> DetectionRules => Set<DetectionRule>();
    public DbSet<AnalysisJob> AnalysisJobs => Set<AnalysisJob>();

    // Phase 4 DbSets
    public DbSet<AiProviderConfig> AiProviderConfigs => Set<AiProviderConfig>();
    public DbSet<AiInvestigationJob> AiInvestigationJobs => Set<AiInvestigationJob>();
    public DbSet<AiInvestigationCheckpoint> AiInvestigationCheckpoints => Set<AiInvestigationCheckpoint>();
    public DbSet<AiInvestigationEvidence> AiInvestigationEvidences => Set<AiInvestigationEvidence>();
    public DbSet<SecurityIntelligenceNode> SecurityIntelligenceNodes => Set<SecurityIntelligenceNode>();
    public DbSet<SecurityIntelligenceEdge> SecurityIntelligenceEdges => Set<SecurityIntelligenceEdge>();
    public DbSet<RepositoryRiskScore> RepositoryRiskScores => Set<RepositoryRiskScore>();

    // Phase 5 DbSets
    public DbSet<CredentialValidationResult> CredentialValidationResults => Set<CredentialValidationResult>();

    // Phase 6 DbSets
    public DbSet<SecurityFinding> SecurityFindings => Set<SecurityFinding>();
    public DbSet<SecurityFindingEvidence> SecurityFindingEvidences => Set<SecurityFindingEvidence>();
    public DbSet<SecurityFindingStatusHistory> SecurityFindingStatusHistories => Set<SecurityFindingStatusHistory>();
    public DbSet<SecurityAlertLog> SecurityAlertLogs => Set<SecurityAlertLog>();

    // Phase 7 DbSets
    public DbSet<RemediationAction> RemediationActions => Set<RemediationAction>();
    public DbSet<RemediationActionHistory> RemediationActionHistories => Set<RemediationActionHistory>();
    public DbSet<RemediationExecution> RemediationExecutions => Set<RemediationExecution>();
    public DbSet<RemediationVerification> RemediationVerifications => Set<RemediationVerification>();

    // Phase 8 DbSets
    public DbSet<SecurityTarget> SecurityTargets => Set<SecurityTarget>();
    public DbSet<SecurityScanJob> SecurityScanJobs => Set<SecurityScanJob>();
    public DbSet<SecurityScanTool> SecurityScanTools => Set<SecurityScanTool>();
    public DbSet<ToolDependency> ToolDependencies => Set<ToolDependency>();
    public DbSet<SecurityProviderCredential> SecurityProviderCredentials => Set<SecurityProviderCredential>();



    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        
        // ... (existing mappings)


        // User
        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("users");
            e.HasKey(u => u.Id);
            e.HasIndex(u => u.Email).IsUnique();
            e.HasIndex(u => u.Username).IsUnique();
            e.Property(u => u.Email).HasMaxLength(256).IsRequired();
            e.Property(u => u.Username).HasMaxLength(100).IsRequired();
            e.Property(u => u.DisplayName).HasMaxLength(200).IsRequired();
            e.Property(u => u.PasswordHash).IsRequired();
        });

        // AuthenticationSession
        modelBuilder.Entity<AuthenticationSession>(e =>
        {
            e.ToTable("authentication_sessions");
            e.HasKey(s => s.Id);
            e.HasIndex(s => s.SessionId).IsUnique();
            e.HasIndex(s => new { s.UserId, s.ExpiresAtUtc });
            e.HasOne(s => s.User).WithMany(u => u.Sessions).HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        // Permission
        modelBuilder.Entity<Permission>(e =>
        {
            e.ToTable("permissions");
            e.HasKey(p => p.Id);
            e.HasIndex(p => p.Code).IsUnique();
            e.Property(p => p.Code).HasMaxLength(100).IsRequired();
            e.Property(p => p.Name).HasMaxLength(200).IsRequired();
            e.Property(p => p.Category).HasMaxLength(100).IsRequired();
        });

        // UserPermission
        modelBuilder.Entity<UserPermission>(e =>
        {
            e.ToTable("user_permissions");
            e.HasKey(up => new { up.UserId, up.PermissionId });
            e.HasOne(up => up.User).WithMany(u => u.UserPermissions).HasForeignKey(up => up.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(up => up.Permission).WithMany(p => p.UserPermissions).HasForeignKey(up => up.PermissionId).OnDelete(DeleteBehavior.Cascade);
        });

        // FieldPermission
        modelBuilder.Entity<FieldPermission>(e =>
        {
            e.ToTable("field_permissions");
            e.HasKey(fp => fp.Id);
            e.HasIndex(fp => new { fp.PermissionCode, fp.ResourceType, fp.FieldName, fp.Action }).IsUnique();
            e.Property(fp => fp.PermissionCode).HasMaxLength(100).IsRequired();
            e.Property(fp => fp.ResourceType).HasMaxLength(100).IsRequired();
            e.Property(fp => fp.FieldName).HasMaxLength(100).IsRequired();
            e.Property(fp => fp.Effect).HasConversion<string>();
            e.Property(fp => fp.Action).HasConversion<string>();
        });

        // AuditEvent
        modelBuilder.Entity<AuditEvent>(e =>
        {
            e.ToTable("audit_events");
            e.HasKey(a => a.Id);
            e.HasIndex(a => a.UserId);
            e.HasIndex(a => a.CorrelationId);
            e.HasIndex(a => a.CreatedAtUtc);
            e.Property(a => a.EventCode).HasConversion<string>().HasMaxLength(100);
            e.Property(a => a.Metadata).HasColumnType("jsonb");
            e.HasOne(a => a.User).WithMany(u => u.AuditEvents).HasForeignKey(a => a.UserId).OnDelete(DeleteBehavior.SetNull);
        });

        // NotificationProviderConfig
        modelBuilder.Entity<NotificationProviderConfig>(e =>
        {
            e.ToTable("notification_provider_configs");
            e.HasKey(n => n.Id);
            e.Property(n => n.Channel).HasConversion<string>();
            e.Property(n => n.Provider).HasConversion<string>();
        });

        // SystemSetting
        modelBuilder.Entity<SystemSetting>(e =>
        {
            e.ToTable("system_settings");
            e.HasKey(s => s.Key);
            e.Property(s => s.ValueType).HasConversion<string>();
        });

        // ApiHunterRecord
        modelBuilder.Entity<ApiHunterRecord>(e =>
        {
            e.ToTable("api_hunter_records");
            e.HasKey(r => r.Id);
            e.HasIndex(r => r.SourceRecordId).IsUnique();
            e.HasIndex(r => new { r.Status, r.ApiType });
            e.Property(r => r.Status).HasConversion<int>();
        });

        // ApiHunterRepoReference
        modelBuilder.Entity<ApiHunterRepoReference>(e =>
        {
            e.ToTable("api_hunter_repo_references");
            e.HasKey(rr => rr.Id);
            e.HasIndex(rr => rr.SourceReferenceId).IsUnique();
            e.HasIndex(rr => new { rr.RepoOwner, rr.RepoName });
            e.HasOne(rr => rr.ApiHunterRecord)
             .WithMany(r => r.RepoReferences)
             .HasForeignKey(rr => rr.ApiHunterRecordId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // ApiHunterSyncState
        modelBuilder.Entity<ApiHunterSyncState>(e =>
        {
            e.ToTable("api_hunter_sync_states");
            e.HasKey(s => s.Id);
            e.Property(s => s.Status).HasConversion<string>();
        });

        // ─────────────────────────────────────────────────────────────────────
        // Phase 3 Configurations
        // ─────────────────────────────────────────────────────────────────────

        // Repository
        modelBuilder.Entity<Repository>(e =>
        {
            e.ToTable("repositories");
            e.HasKey(r => r.Id);
            e.HasIndex(r => new { r.Provider, r.ProviderRepoId }).IsUnique();
            e.HasIndex(r => new { r.Owner, r.Name });
            e.HasIndex(r => r.AcquisitionStatus);
            e.Property(r => r.Provider).HasMaxLength(50).IsRequired();
            e.Property(r => r.Owner).HasMaxLength(256).IsRequired();
            e.Property(r => r.Name).HasMaxLength(256).IsRequired();
            e.Property(r => r.FullName).HasMaxLength(512).IsRequired();
            e.Property(r => r.AcquisitionStatus).HasConversion<string>().HasMaxLength(50);
            e.Property(r => r.RowVersion).IsRowVersion();
        });

        // RepositorySource
        modelBuilder.Entity<RepositorySource>(e =>
        {
            e.ToTable("repository_sources");
            e.HasKey(rs => rs.Id);
            e.HasIndex(rs => new { rs.RepositoryId, rs.ApiHunterRecordId, rs.ApiHunterRepoRefId }).IsUnique();
            e.HasIndex(rs => rs.RepositoryId);
            e.HasIndex(rs => rs.ApiHunterRecordId);
            e.Property(rs => rs.DiscoveryType).HasConversion<string>().HasMaxLength(50);
            e.HasOne(rs => rs.Repository)
             .WithMany(r => r.Sources)
             .HasForeignKey(rs => rs.RepositoryId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(rs => rs.ApiHunterRecord)
             .WithMany()
             .HasForeignKey(rs => rs.ApiHunterRecordId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // RepositorySnapshot
        modelBuilder.Entity<RepositorySnapshot>(e =>
        {
            e.ToTable("repository_snapshots");
            e.HasKey(s => s.Id);
            e.HasIndex(s => new { s.RepositoryId, s.CommitSha }).IsUnique();
            e.HasIndex(s => s.AnalysisStatus);
            e.HasIndex(s => s.AcquiredAtUtc);
            e.Property(s => s.CommitSha).HasMaxLength(40).IsRequired();
            e.Property(s => s.BranchName).HasMaxLength(256).IsRequired();
            e.Property(s => s.AnalysisStatus).HasConversion<string>().HasMaxLength(50);
            e.HasOne(s => s.Repository)
             .WithMany(r => r.Snapshots)
             .HasForeignKey(s => s.RepositoryId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // SnapshotFile
        modelBuilder.Entity<SnapshotFile>(e =>
        {
            e.ToTable("snapshot_files");
            e.HasKey(sf => sf.Id);
            e.HasIndex(sf => sf.SnapshotId);
            e.HasIndex(sf => sf.ContentHash);
            e.Property(sf => sf.FilePath).IsRequired();
            e.Property(sf => sf.FileName).HasMaxLength(512).IsRequired();
            e.Property(sf => sf.FileExtension).HasMaxLength(50);
            e.Property(sf => sf.ContentHash).HasMaxLength(64).IsRequired();
            e.Property(sf => sf.SkipReason).HasConversion<string>().HasMaxLength(100);
            e.HasOne(sf => sf.Snapshot)
             .WithMany(s => s.Files)
             .HasForeignKey(sf => sf.SnapshotId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // CredentialCandidate
        modelBuilder.Entity<CredentialCandidate>(e =>
        {
            e.ToTable("credential_candidates");
            e.HasKey(cc => cc.Id);
            e.HasIndex(cc => cc.SecretFingerprint).IsUnique();
            e.HasIndex(cc => cc.Status);
            e.HasIndex(cc => cc.CredentialType);
            e.Property(cc => cc.SecretFingerprint).HasMaxLength(64).IsRequired();
            e.Property(cc => cc.MaskedValue).HasMaxLength(256).IsRequired();
            e.Property(cc => cc.EncryptedRawValue).IsRequired();
            e.Property(cc => cc.CredentialType).HasMaxLength(100).IsRequired();
            e.Property(cc => cc.Status).HasConversion<string>().HasMaxLength(50);
            e.HasOne(cc => cc.ResolvedByUser)
             .WithMany()
             .HasForeignKey(cc => cc.ResolvedByUserId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // DetectionRule (Composite Key: Id + Version)
        modelBuilder.Entity<DetectionRule>(e =>
        {
            e.ToTable("detection_rules");
            e.HasKey(dr => new { dr.Id, dr.Version });
            e.Property(dr => dr.Id).HasMaxLength(100).IsRequired();
            e.Property(dr => dr.CredentialType).HasMaxLength(100).IsRequired();
            e.Property(dr => dr.Confidence).HasMaxLength(20).IsRequired();
            e.Property(dr => dr.Source).HasConversion<string>().HasMaxLength(50);
        });

        // CandidateOccurrence
        modelBuilder.Entity<CandidateOccurrence>(e =>
        {
            e.ToTable("candidate_occurrences");
            e.HasKey(co => co.Id);
            e.HasIndex(co => co.OccurrenceFingerprint).IsUnique();
            e.HasIndex(co => co.CandidateId);
            e.HasIndex(co => co.SnapshotFileId);
            e.HasIndex(co => co.RepositoryId);
            e.Property(co => co.OccurrenceFingerprint).HasMaxLength(64).IsRequired();
            e.Property(co => co.Confidence).HasMaxLength(20).IsRequired();
            e.HasOne(co => co.Candidate)
             .WithMany(cc => cc.Occurrences)
             .HasForeignKey(co => co.CandidateId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(co => co.SnapshotFile)
             .WithMany(sf => sf.Occurrences)
             .HasForeignKey(co => co.SnapshotFileId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(co => co.Repository)
             .WithMany(r => r.Occurrences)
             .HasForeignKey(co => co.RepositoryId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(co => co.DetectionRule)
             .WithMany(dr => dr.Occurrences)
             .HasForeignKey(co => new { co.DetectionRuleId, co.RuleVersion })
             .OnDelete(DeleteBehavior.Restrict);
        });

        // AnalysisJob
        modelBuilder.Entity<AnalysisJob>(e =>
        {
            e.ToTable("analysis_jobs");
            e.HasKey(j => j.Id);
            e.HasIndex(j => new { j.Status, j.Priority, j.QueuedAtUtc });
            e.HasIndex(j => j.LastHeartbeatAtUtc);
            e.Property(j => j.JobType).HasConversion<string>().HasMaxLength(50);
            e.Property(j => j.Status).HasConversion<string>().HasMaxLength(50);
            e.Property(j => j.TargetEntityType).HasMaxLength(50).IsRequired();
            e.Property(j => j.RowVersion).IsRowVersion();
            e.HasOne(j => j.QueuedByUser)
             .WithMany()
             .HasForeignKey(j => j.QueuedByUserId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // ─────────────────────────────────────────────────────────────────────
        // Phase 4 Configurations
        // ─────────────────────────────────────────────────────────────────────

        // AiProviderConfig
        modelBuilder.Entity<AiProviderConfig>(e =>
        {
            e.ToTable("ai_provider_configs");
            e.HasKey(p => p.Id);
            e.HasIndex(p => new { p.ProviderName, p.ModelName }).IsUnique();
            e.HasIndex(p => new { p.IsEnabled, p.Priority, p.HealthStatus });
            e.Property(p => p.ProviderName).HasMaxLength(100).IsRequired();
            e.Property(p => p.ModelName).HasMaxLength(100).IsRequired();
            e.Property(p => p.EncryptedApiKey).IsRequired();
            e.Property(p => p.CapabilitiesJson).HasColumnType("jsonb");
            e.Property(p => p.HealthStatus).HasConversion<string>().HasMaxLength(50);
        });


        // AiInvestigationJob
        modelBuilder.Entity<AiInvestigationJob>(e =>
        {
            e.ToTable("ai_investigation_jobs");
            e.HasKey(j => j.Id);
            e.HasIndex(j => new { j.Status, j.CurrentStage, j.QueuedAtUtc });
            e.HasIndex(j => j.RepositoryId);
            e.HasIndex(j => j.SnapshotId);
            e.HasIndex(j => j.ClaimToken);
            e.Property(j => j.ClaimToken).IsConcurrencyToken();
            e.Property(j => j.CurrentStage).HasConversion<string>().HasMaxLength(50);


            e.Property(j => j.Status).HasConversion<string>().HasMaxLength(50);
            e.Property(j => j.ActiveProviderName).HasMaxLength(100);
            e.Property(j => j.ActiveModelName).HasMaxLength(100);
            e.HasOne(j => j.Repository)
             .WithMany()
             .HasForeignKey(j => j.RepositoryId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(j => j.Snapshot)
             .WithMany()
             .HasForeignKey(j => j.SnapshotId)
             .OnDelete(DeleteBehavior.Restrict);
        });

        // AiInvestigationCheckpoint
        modelBuilder.Entity<AiInvestigationCheckpoint>(e =>
        {
            e.ToTable("ai_investigation_checkpoints");
            e.HasKey(c => c.Id);
            e.HasIndex(c => new { c.InvestigationJobId, c.StageType }).IsUnique();
            e.Property(c => c.StageType).HasConversion<string>().HasMaxLength(50);
            e.Property(c => c.CursorPosition).HasMaxLength(512);
            e.Property(c => c.DurableResultJson).HasColumnType("jsonb");
            e.HasOne(c => c.InvestigationJob)
             .WithMany(j => j.Checkpoints)
             .HasForeignKey(c => c.InvestigationJobId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // AiInvestigationEvidence
        modelBuilder.Entity<AiInvestigationEvidence>(e =>
        {
            e.ToTable("ai_investigation_evidences");
            e.HasKey(ev => ev.Id);
            e.HasIndex(ev => ev.InvestigationId);
            e.HasIndex(ev => ev.SnapshotId);
            e.HasIndex(ev => ev.SnapshotFileId);
            e.HasIndex(ev => ev.CandidateId);
            e.HasIndex(ev => ev.Fingerprint);
            e.Property(ev => ev.EvidenceType).HasMaxLength(100).IsRequired();

            e.Property(ev => ev.FilePath).HasMaxLength(1024).IsRequired();
            e.Property(ev => ev.Confidence).HasConversion<string>().HasMaxLength(20);
            e.Property(ev => ev.Source).HasConversion<string>().HasMaxLength(50);
            e.Property(ev => ev.EvidenceJson).HasColumnType("jsonb");
            e.HasOne(ev => ev.Investigation)
             .WithMany(j => j.Evidences)
             .HasForeignKey(ev => ev.InvestigationId)
             .OnDelete(DeleteBehavior.SetNull);

            e.HasOne(ev => ev.Snapshot)
             .WithMany()
             .HasForeignKey(ev => ev.SnapshotId)
             .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(ev => ev.SnapshotFile)
             .WithMany()
             .HasForeignKey(ev => ev.SnapshotFileId)
             .OnDelete(DeleteBehavior.SetNull);
            e.HasOne(ev => ev.Candidate)
             .WithMany()
             .HasForeignKey(ev => ev.CandidateId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // SecurityIntelligenceNode
        modelBuilder.Entity<SecurityIntelligenceNode>(e =>
        {
            e.ToTable("security_intelligence_nodes");
            e.HasKey(n => n.Id);
            e.HasIndex(n => new { n.NodeType, n.Name }).IsUnique();
            e.HasIndex(n => n.NodeType);
            e.HasIndex(n => n.RelatedEntityId);
            e.Property(n => n.NodeType).HasConversion<string>().HasMaxLength(50);
            e.Property(n => n.Name).HasMaxLength(256).IsRequired();
            e.Property(n => n.Label).HasMaxLength(256);
            e.Property(n => n.MetadataJson).HasColumnType("jsonb");
        });

        // SecurityIntelligenceEdge
        modelBuilder.Entity<SecurityIntelligenceEdge>(e =>
        {
            e.ToTable("security_intelligence_edges");
            e.HasKey(eg => eg.Id);
            e.HasIndex(eg => new { eg.SourceNodeId, eg.TargetNodeId, eg.EdgeType }).IsUnique();
            e.HasIndex(eg => eg.SourceNodeId);
            e.HasIndex(eg => eg.TargetNodeId);
            e.Property(eg => eg.EdgeType).HasConversion<string>().HasMaxLength(50);
            e.Property(eg => eg.DiscoverySource).HasConversion<string>().HasMaxLength(50);
            e.Property(eg => eg.Confidence).HasConversion<string>().HasMaxLength(20);
            e.Property(eg => eg.EvidenceReference).HasMaxLength(512);
            e.HasOne(eg => eg.SourceNode)
             .WithMany(n => n.OutgoingEdges)
             .HasForeignKey(eg => eg.SourceNodeId)
             .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(eg => eg.TargetNode)
             .WithMany(n => n.IncomingEdges)
             .HasForeignKey(eg => eg.TargetNodeId)
             .OnDelete(DeleteBehavior.Restrict);
        });

        // RepositoryRiskScore
        modelBuilder.Entity<RepositoryRiskScore>(e =>
        {
            e.ToTable("repository_risk_scores");
            e.HasKey(s => s.Id);
            e.HasIndex(s => new { s.RepositoryId, s.CalculatedAtUtc });
            e.HasIndex(s => s.Severity);
            e.Property(s => s.Severity).HasConversion<string>().HasMaxLength(20);
            e.Property(s => s.AlgorithmVersion).HasMaxLength(20).IsRequired();
            e.Property(s => s.FactorBreakdownJson).HasColumnType("jsonb");
            e.HasOne(s => s.Repository)
             .WithMany()
             .HasForeignKey(s => s.RepositoryId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // CredentialValidationResult
        modelBuilder.Entity<CredentialValidationResult>(e =>
        {
            e.ToTable("credential_validation_results");
            e.HasKey(r => r.Id);
            e.HasIndex(r => new { r.CandidateId, r.ValidatedAtUtc });
            e.HasIndex(r => new { r.Status, r.ProviderName });
            // Phase 6 Step 6: composite index for processor eligibility query
            e.HasIndex(r => new { r.ProcessedForFindingAtUtc, r.ValidatedAtUtc });
            e.Property(r => r.ProviderName).HasMaxLength(100).IsRequired();
            e.Property(r => r.Status).HasConversion<string>().HasMaxLength(50);
            e.Property(r => r.Confidence).HasConversion<string>().HasMaxLength(20);
            e.Property(r => r.ValidatorVersion).HasMaxLength(20).IsRequired();
            e.Property(r => r.PolicyVersion).HasMaxLength(20).IsRequired();
            e.Property(r => r.ResponseClassification).HasMaxLength(256);
            e.Property(r => r.SafeEvidenceJson).HasColumnType("jsonb");
            // Phase 6 Step 6 — processing state columns
            e.Property(r => r.ProcessedForFindingAtUtc).IsRequired(false);
            e.Property(r => r.ProcessingClaimToken).IsRequired(false);
            e.Property(r => r.ProcessingClaimedAtUtc).IsRequired(false);
            e.HasOne(r => r.Candidate)
             .WithMany()
             .HasForeignKey(r => r.CandidateId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(r => r.AnalysisJob)
             .WithMany()
             .HasForeignKey(r => r.AnalysisJobId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // SecurityFinding
        modelBuilder.Entity<SecurityFinding>(e =>
        {
            e.ToTable("security_findings");
            e.HasKey(f => f.Id);
            e.HasIndex(f => f.FindingFingerprint).IsUnique();
            e.HasIndex(f => new { f.RepositoryId, f.Status });
            e.HasIndex(f => new { f.Severity, f.Confidence });
            e.Property(f => f.FindingFingerprint).HasMaxLength(128).IsRequired();
            e.Property(f => f.Title).HasMaxLength(256).IsRequired();
            e.Property(f => f.Description).IsRequired();
            e.Property(f => f.FindingType).HasConversion<string>().HasMaxLength(50);
            e.Property(f => f.Severity).HasConversion<string>().HasMaxLength(20);
            e.Property(f => f.Confidence).HasConversion<string>().HasMaxLength(20);
            e.Property(f => f.Status).HasConversion<string>().HasMaxLength(30);
            e.Property(f => f.RiskFactorBreakdownJson).HasColumnType("jsonb");
            e.Property(f => f.LifecycleVersion).IsConcurrencyToken();
            e.HasOne(f => f.Repository)
             .WithMany()
             .HasForeignKey(f => f.RepositoryId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(f => f.Snapshot)
             .WithMany()
             .HasForeignKey(f => f.SnapshotId)
             .OnDelete(DeleteBehavior.SetNull);
            e.HasOne(f => f.ResolvedByUser)
             .WithMany()
             .HasForeignKey(f => f.ResolvedByUserId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // SecurityFindingEvidence
        modelBuilder.Entity<SecurityFindingEvidence>(e =>
        {
            e.ToTable("security_finding_evidence");
            e.HasKey(ev => ev.Id);
            e.HasIndex(ev => new { ev.FindingId, ev.EvidenceFingerprint }).IsUnique();
            e.Property(ev => ev.EvidenceFingerprint).HasMaxLength(128).IsRequired();
            e.Property(ev => ev.EvidenceType).HasConversion<string>().HasMaxLength(50);
            e.Property(ev => ev.DiscoverySource).HasConversion<string>().HasMaxLength(50);
            e.Property(ev => ev.EvidenceReference).HasMaxLength(512);
            e.Property(ev => ev.SafeEvidenceJson).HasColumnType("jsonb");
            e.HasOne(ev => ev.Finding)
             .WithMany(f => f.Evidences)
             .HasForeignKey(ev => ev.FindingId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // SecurityFindingStatusHistory
        modelBuilder.Entity<SecurityFindingStatusHistory>(e =>
        {
            e.ToTable("security_finding_status_histories");
            e.HasKey(h => h.Id);
            e.HasIndex(h => h.FindingId);
            e.HasIndex(h => h.CreatedAtUtc);
            e.Property(h => h.FromStatus).HasConversion<string>().HasMaxLength(30);
            e.Property(h => h.ToStatus).HasConversion<string>().HasMaxLength(30);
            e.Property(h => h.Reason).HasMaxLength(1024).IsRequired();
            e.Property(h => h.MetadataJson).HasColumnType("jsonb");
            e.HasOne(h => h.Finding)
             .WithMany(f => f.StatusHistories)
             .HasForeignKey(h => h.FindingId)
             .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(h => h.ChangedByUser)
             .WithMany()
             .HasForeignKey(h => h.ChangedByUserId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // SecurityAlertLog
        modelBuilder.Entity<SecurityAlertLog>(e =>
        {
            e.ToTable("security_alert_logs");
            e.HasKey(a => a.Id);
            e.HasIndex(a => new { a.AlertFingerprint, a.SentAtUtc });
            e.HasIndex(a => a.FindingFingerprint);
            e.Property(a => a.FindingFingerprint).HasMaxLength(128).IsRequired();
            e.Property(a => a.AlertReason).HasMaxLength(100).IsRequired();
            e.Property(a => a.AlertFingerprint).HasMaxLength(128).IsRequired();
            e.Property(a => a.Severity).HasConversion<string>().HasMaxLength(20);
            e.Property(a => a.Recipient).HasMaxLength(256).IsRequired();
        });

        // RemediationAction
        modelBuilder.Entity<RemediationAction>(e =>
        {
            e.ToTable("remediation_actions");
            e.HasKey(ra => ra.Id);
            e.HasIndex(ra => ra.ActionFingerprint).IsUnique();
            e.HasIndex(ra => ra.FindingId);
            e.HasIndex(ra => ra.RepositoryId);
            e.HasIndex(ra => ra.Status);
            e.HasIndex(ra => ra.CreatedAtUtc);
            e.HasIndex(ra => ra.ExpiresAtUtc);
            e.Property(ra => ra.Version).IsConcurrencyToken();
            e.Property(ra => ra.ActionFingerprint).HasMaxLength(128).IsRequired();
            e.Property(ra => ra.ActionType).HasConversion<string>().HasMaxLength(50);
            e.Property(ra => ra.Status).HasConversion<string>().HasMaxLength(50);
            e.Property(ra => ra.Title).HasMaxLength(256).IsRequired();
            e.Property(ra => ra.Description).HasMaxLength(2048);
            e.Property(ra => ra.ProviderKey).HasMaxLength(100);
            e.Property(ra => ra.ProviderResourceReference).HasMaxLength(512);

            e.HasOne(ra => ra.Finding)
             .WithMany(f => f.RemediationActions)
             .HasForeignKey(ra => ra.FindingId)
             .OnDelete(DeleteBehavior.Restrict);

            e.HasOne(ra => ra.Repository)
             .WithMany()
             .HasForeignKey(ra => ra.RepositoryId)
             .OnDelete(DeleteBehavior.Restrict);

            e.HasOne(ra => ra.ProposedByUser)
             .WithMany()
             .HasForeignKey(ra => ra.ProposedByUserId)
             .OnDelete(DeleteBehavior.SetNull);

            e.HasOne(ra => ra.ApprovedByUser)
             .WithMany()
             .HasForeignKey(ra => ra.ApprovedByUserId)
             .OnDelete(DeleteBehavior.SetNull);

            e.HasOne(ra => ra.RejectedByUser)
             .WithMany()
             .HasForeignKey(ra => ra.RejectedByUserId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // RemediationActionHistory
        modelBuilder.Entity<RemediationActionHistory>(e =>
        {
            e.ToTable("remediation_action_histories");
            e.HasKey(rah => rah.Id);
            e.HasIndex(rah => rah.RemediationActionId);
            e.HasIndex(rah => rah.CreatedAtUtc);
            e.Property(rah => rah.FromStatus).HasConversion<string>().HasMaxLength(50);
            e.Property(rah => rah.ToStatus).HasConversion<string>().HasMaxLength(50);
            e.Property(rah => rah.Reason).HasMaxLength(1024).IsRequired();
            e.Property(rah => rah.MetadataJson).HasColumnType("jsonb");

            e.HasOne(rah => rah.RemediationAction)
             .WithMany(ra => ra.Histories)
             .HasForeignKey(rah => rah.RemediationActionId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(rah => rah.ChangedByUser)
             .WithMany()
             .HasForeignKey(rah => rah.ChangedByUserId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // RemediationExecution
        modelBuilder.Entity<RemediationExecution>(e =>
        {
            e.ToTable("remediation_executions");
            e.HasKey(re => re.Id);
            e.HasIndex(re => new { re.RemediationActionId, re.ActionVersion }).IsUnique();
            e.HasIndex(re => re.Status);
            e.HasIndex(re => re.StartedAtUtc);
            e.Property(re => re.Status).HasConversion<string>().HasMaxLength(50);
            e.Property(re => re.ProviderKey).HasMaxLength(100).IsRequired();
            e.Property(re => re.ProviderResourceReference).HasMaxLength(500);
            e.Property(re => re.FailureCode).HasMaxLength(100);
            e.Property(re => re.FailureReason).HasMaxLength(1024);
            e.Property(re => re.ProviderOperationId).HasMaxLength(200);

            e.HasOne(re => re.RemediationAction)
             .WithMany(ra => ra.Executions)
             .HasForeignKey(re => re.RemediationActionId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // RemediationVerification
        modelBuilder.Entity<RemediationVerification>(e =>
        {
            e.ToTable("remediation_verifications");
            e.HasKey(rv => rv.Id);
            e.HasIndex(rv => rv.RemediationActionId).IsUnique();
            e.HasIndex(rv => rv.Status);
            e.Property(rv => rv.Status).HasConversion<string>().HasMaxLength(50);
            e.Property(rv => rv.ValidationResultStatus).HasMaxLength(100);
            e.Property(rv => rv.VerificationDetailsJson).HasColumnType("jsonb");

            e.HasOne(rv => rv.RemediationAction)
             .WithOne(ra => ra.Verification)
             .HasForeignKey<RemediationVerification>(rv => rv.RemediationActionId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(rv => rv.RemediationExecution)
             .WithMany()
             .HasForeignKey(rv => rv.RemediationExecutionId)
             .OnDelete(DeleteBehavior.SetNull);
        });

        // SecurityTarget
        modelBuilder.Entity<SecurityTarget>(e =>
        {
            e.ToTable("security_targets");
            e.HasKey(st => st.Id);
            e.HasIndex(st => st.BaseUrl);
            e.Property(st => st.Name).HasMaxLength(200).IsRequired();
            e.Property(st => st.BaseUrl).HasMaxLength(1024).IsRequired();
            e.Property(st => st.TargetType).HasMaxLength(100).IsRequired();
        });

        // SecurityScanJob
        modelBuilder.Entity<SecurityScanJob>(e =>
        {
            e.ToTable("security_scan_jobs");
            e.HasKey(sj => sj.Id);
            e.HasIndex(sj => sj.Status);
            e.HasIndex(sj => sj.TargetUrl);
            e.HasIndex(sj => sj.CreatedAtUtc);
            e.Property(sj => sj.TargetUrl).HasMaxLength(1024).IsRequired();
            e.Property(sj => sj.ProviderKey).HasMaxLength(100).IsRequired();
            e.Property(sj => sj.CorrelationId).HasMaxLength(100).IsRequired();
            e.Property(sj => sj.ScanProfile).HasConversion<string>().HasMaxLength(50);
            e.Property(sj => sj.Status).HasConversion<string>().HasMaxLength(50);
            e.Property(sj => sj.Version).IsConcurrencyToken();

            e.HasOne(sj => sj.Target)
             .WithMany()
             .HasForeignKey(sj => sj.TargetId)
             .OnDelete(DeleteBehavior.SetNull);

            e.HasOne(sj => sj.Repository)
             .WithMany()
             .HasForeignKey(sj => sj.RepositoryId)
             .OnDelete(DeleteBehavior.SetNull);

            e.HasOne(sj => sj.RequestedByUser)
             .WithMany()
             .HasForeignKey(sj => sj.RequestedByUserId)
             .OnDelete(DeleteBehavior.Restrict);
        });

        // SecurityScanTool
        modelBuilder.Entity<SecurityScanTool>(e =>
        {
            e.ToTable("security_scan_tools");
            e.HasKey(st => st.Id);
            e.HasIndex(st => st.ToolKey).IsUnique();
            e.Property(st => st.ToolKey).HasMaxLength(100).IsRequired();
            e.Property(st => st.DisplayName).HasMaxLength(200).IsRequired();
            e.Property(st => st.Version).HasMaxLength(100).IsRequired();
            e.Property(st => st.Executable).HasMaxLength(200).IsRequired();
            e.Property(st => st.ArtifactSourceType).HasMaxLength(100);
            e.Property(st => st.ArtifactRepository).HasMaxLength(256);
            e.Property(st => st.ArtifactUrl).HasMaxLength(1024);
            e.Property(st => st.ArtifactFormat).HasMaxLength(50);
            e.Property(st => st.CapabilityProbeCommand).HasMaxLength(100);
            e.Property(st => st.CapabilityProbeExpectedKeyword).HasMaxLength(100);
            e.Property(st => st.ArtifactSha256).HasMaxLength(128);
            e.Property(st => st.ArtifactSignature).HasMaxLength(512);
            e.Property(st => st.ContainerImageDigest).HasMaxLength(128);
            e.Property(st => st.CapabilitiesJson).HasColumnType("jsonb");
            e.Property(st => st.HealthStatus).HasConversion<string>().HasMaxLength(50);
        });

        // ToolDependency
        modelBuilder.Entity<ToolDependency>(e =>
        {
            e.ToTable("tool_dependencies");
            e.HasKey(td => td.Id);
            e.HasIndex(td => new { td.ParentToolKey, td.DependencyToolKey }).IsUnique();
            e.Property(td => td.ParentToolKey).HasMaxLength(100).IsRequired();
            e.Property(td => td.DependencyToolKey).HasMaxLength(100).IsRequired();
            e.Property(td => td.RequiredVersion).HasMaxLength(100).IsRequired();
            e.Property(td => td.RequiredSha256).HasMaxLength(128).IsRequired();
        });

        // SecurityProviderCredential
        modelBuilder.Entity<SecurityProviderCredential>(e =>
        {
            e.ToTable("security_provider_credentials");
            e.HasKey(pc => pc.Id);
            e.HasIndex(pc => new { pc.ProviderKey, pc.SecretReference }).IsUnique();
            e.Property(pc => pc.ProviderKey).HasMaxLength(100).IsRequired();
            e.Property(pc => pc.SecretReference).HasMaxLength(250).IsRequired();
            e.Property(pc => pc.CredentialType).HasMaxLength(100).IsRequired();
            e.Property(pc => pc.ValidationStatus).HasMaxLength(50);
        });
    }

    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        if (Database.ProviderName == "Microsoft.EntityFrameworkCore.InMemory")
        {
            var addedFindings = ChangeTracker.Entries<SecurityFinding>()
                .Where(e => e.State == EntityState.Added)
                .Select(e => e.Entity.FindingFingerprint)
                .ToList();

            if (addedFindings.Count > 0)
            {
                var existing = await SecurityFindings.AsNoTracking()
                    .Where(f => addedFindings.Contains(f.FindingFingerprint))
                    .Select(f => f.FindingFingerprint)
                    .FirstOrDefaultAsync(cancellationToken);

                if (existing != null)
                {
                    throw new DbUpdateException($"Duplicate key value violates unique index 'IX_security_findings_finding_fingerprint' on finding fingerprint '{existing}'.");
                }
            }
        }

        return await base.SaveChangesAsync(cancellationToken);
    }
}





