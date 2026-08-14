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
    CredentialRevealed,

    // Phase 3 — Repositories & Acquisition
    RepositoryAdded,
    RepositoryAcquisitionTriggered,
    BulkRepositoryAcquisitionTriggered,
    RepositoryAcquired,
    RepositoryAcquisitionFailed,
    RepositoryDisabled,

    // Phase 3 — Snapshots & Analysis
    SnapshotCreated,
    SnapshotAnalysisCompleted,
    SnapshotAnalysisFailed,

    // Phase 3 — Secret Candidates & Occurrences
    SecretCandidateDetected,
    SecretCandidateRevealed,
    SecretCandidateStatusChanged,
    SecretCandidateResolved,
    RawContextsPurged,

    // Phase 3 — Detection Rules & Jobs
    DetectionRuleToggled,
    DetectionRuleCreated,
    JobCreated,
    JobCancelled,
    JobPaused,
    JobResumed,
    JobRetried,
    JobFailed,
    JobSucceeded,

    // Phase 4 — AI Investigation & Security Intelligence Graph
    AiProviderConfigured,
    AiProviderToggled,
    AiProviderTested,
    AiProviderCooldownReset,
    AiGlobalPause,
    AiGlobalResume,
    AiInvestigationTriggered,
    AiInvestigationCompleted,
    AiInvestigationFailed,
    AiInvestigationStageCheckpoint,
    SecurityGraphUpdated,
    GraphRebuildRequested,
    GraphBuildCompleted,
    RiskScoreCalculated,
    GraphIntelligenceAnalysisCompleted,
    FindingStatusChanged,

    // Phase 6 — Continuous Revalidation & Alerting
    CredentialRevalidationProcessed,
    AlertSuppressedByCooldown,

    // Phase 7 — Remediation Response
    RemediateActionProposed,
    RemediateActionStatusChanged,
    RemediateActionApproved,
    RemediateActionRejected,
    RemediateActionCancelled,
    RemediateActionPolicyEvaluated,
    RemediateActionPolicySuppressed,
    RemediateActionExecutionStarted,
    RemediateActionExecutionCompleted,
    RemediateActionExecutionFailed,
    RemediateActionVerificationStarted,
    RemediateActionVerificationCompleted,
    RemediateActionVerificationFailed,

    // Phase 8 — Hosted Security Scanning & Provider Foundation
    ScanJobCreated,
    ScanJobStatusChanged,
    ScanJobCancelled,
    ScanJobRetried,
    ScanToolRegistered,
    ScanToolStatusChanged,
    ScanProviderConfigured,
    ScanFindingsIngested
}

public enum ToolFailureClassification
{
    None = 0,
    SecurityBoundary = 1,
    ToolExecution = 2,
    Infrastructure = 3,
    Cancelled = 4
}

public enum SecurityScanJobStatus
{
    Queued,
    Validating,
    Running,
    Completed,
    CompletedWithWarnings,
    Partial,
    Failed,
    Cancelled,
    TimedOut,
    Blocked
}

public enum SecurityScanProfileType
{
    Recon = 0,
    WebAssessment = 1,
    Standard = 1,
    FullAssessment = 2,
    Deep = 2
}

public enum ToolOutputFormat
{
    Json,
    JsonLines,
    Sarif,
    Xml,
    PlainText
}

public enum ToolCapability
{
    SubdomainEnumeration,
    DnsResolution,
    HttpProbing,
    UrlCrawling,
    VulnerabilityScanning,
    Fuzzing,
    SecretScanning,
    Web3Analysis,
    AiAssistedHunting,
    ReportGeneration
}

public enum ToolHealthStatus
{
    Healthy,
    Degraded,
    Missing,
    Unreachable,
    Disabled
}

public enum ToolExecutionStatus
{
    Success,
    Warning,
    Failed,
    TimedOut,
    Cancelled,
    Skipped
}

public enum ScannerRuntimeMode
{
    LocalDocker,
    CloudManagedContainer,
    UnsafeLocalProcessFallback,
    Docker = LocalDocker,
    Hosted = CloudManagedContainer
}

public enum EgressGatewayMode
{
    EnforcedGateway,
    IsolatedNetwork,
    None
}

public enum RemediationVerificationStatus
{
    Pending,
    Verified,
    VerificationFailed
}

public enum RemediationExecutionStatus
{
    Pending,
    Executing,
    Succeeded,
    Failed,
    Cancelled,
    VerificationPending,
    Verified,
    VerificationFailed
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

public enum AcquisitionStatus
{
    Pending,
    Acquired,
    Failed,
    Disabled
}

public enum AnalysisStatus
{
    Pending,
    Analyzing,
    Completed,
    Failed
}

public enum CandidateStatus
{
    Detected,
    Triaged,
    Resolved
}

public enum JobStatus
{
    Queued,
    Running,
    Succeeded,
    Failed,
    Retrying,
    Cancelled,
    Paused
}

public enum JobType
{
    RepositoryAcquisition,
    SnapshotAnalysis,
    AiInvestigation,
    CredentialValidation
}


public enum DiscoveryType
{
    ApiHunterSync,
    AdminManual,
    AiInvestigator,
    DeterministicDetector,
    CredentialValidation
}


public enum RuleSource
{
    BuiltIn,
    Custom,
    GitleaksImport
}

public enum SkipReason
{
    Binary,
    TooLarge,
    VendoredLib,
    AllowListed
}

public enum AiInvestigationStageType
{
    RepositoryMetadata = 1,
    FileInventory = 2,
    TechnologyIdentification = 3,
    ApiHunterSeedInvestigation = 4,
    ConfigurationAnalysis = 5,
    CandidateDiscovery = 6,
    CrossFileRelationshipAnalysis = 7,
    CredentialServiceRelationshipAnalysis = 8,
    ProductionExposureAnalysis = 9,
    FinalIntelligenceReport = 10
}

public enum FindingType
{
    ValidatedCredentialExposed,
    UnvalidatedCredentialExposed,
    ProductionServiceExposed,
    HistoricalExposureDetected,
    OverprivilegedCredential,
    DatabaseExposure,
    /// <summary>Credential confirmed expired by provider.</summary>
    ExpiredCredentialExposed,
    /// <summary>Credential explicitly revoked by provider.</summary>
    RevokedCredentialExposed
}

public enum FindingStatus
{
    Open,
    Investigating,
    Confirmed,
    Remediated,
    AcceptedRisk,
    FalsePositive,
    Resolved
}

public enum FindingEvidenceType
{
    ApiHunterSeed,
    DeterministicOccurrence,
    AiInvestigationEvidence,
    ValidationResult,
    IntelligenceNode,
    IntelligenceEdge,
    HistoricalCommit
}


public enum AiHealthStatus
{
    Healthy,
    Degraded,
    RateLimited,
    Unreachable,
    Disabled
}

public enum IntelligenceNodeType
{
    Repository,
    CredentialCandidate,
    Service,
    Domain,
    Environment,
    Database
}

public enum IntelligenceEdgeType
{
    DiscoveredIn,
    AppearsIn,
    RelatedTo,
    UsedBy,
    AssociatedWith,
    BelongsTo
}

public enum FindingConfidence
{
    Low,
    Medium,
    High
}

public enum RiskSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum RemediationActionType
{
    RevokeCredential,
    RotateCredential,
    RestrictCredentialScope,
    RemoveCurrentExposure,
    RemoveHistoricalExposure,
    DisableExposedService,
    InvestigateExposure
}

public enum RemediationActionStatus
{
    Proposed,
    PendingApproval,
    Approved,
    Rejected,
    Executing,
    Succeeded,
    Failed,
    Cancelled,
    VerificationPending,
    Verified,
    VerificationFailed
}



