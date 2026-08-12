using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase3Tables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "analysis_jobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    JobType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Priority = table.Column<int>(type: "integer", nullable: false),
                    TargetEntityType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    TargetEntityId = table.Column<Guid>(type: "uuid", nullable: false),
                    PayloadJson = table.Column<string>(type: "text", nullable: true),
                    ResultJson = table.Column<string>(type: "text", nullable: true),
                    ErrorMessage = table.Column<string>(type: "text", nullable: true),
                    RetryCount = table.Column<int>(type: "integer", nullable: false),
                    MaxRetries = table.Column<int>(type: "integer", nullable: false),
                    CheckpointFileId = table.Column<Guid>(type: "uuid", nullable: true),
                    WorkerInstanceId = table.Column<string>(type: "text", nullable: true),
                    QueuedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastHeartbeatAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NextRetryAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    QueuedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    CorrelationId = table.Column<string>(type: "text", nullable: false),
                    RowVersion = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_analysis_jobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_analysis_jobs_users_QueuedByUserId",
                        column: x => x.QueuedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "credential_candidates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SecretFingerprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    FingerprintKeyVersion = table.Column<int>(type: "integer", nullable: false),
                    MaskedValue = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    EncryptedRawValue = table.Column<string>(type: "text", nullable: false),
                    CredentialType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    FirstDetectedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastDetectedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    TotalOccurrences = table.Column<int>(type: "integer", nullable: false),
                    ResolvedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ResolvedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ResolutionNote = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_credential_candidates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_credential_candidates_users_ResolvedByUserId",
                        column: x => x.ResolvedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "detection_rules",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false),
                    RegexPattern = table.Column<string>(type: "text", nullable: false),
                    CredentialType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Confidence = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    TagsJson = table.Column<string>(type: "text", nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    AllowlistPatternsJson = table.Column<string>(type: "text", nullable: true),
                    Source = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_detection_rules", x => new { x.Id, x.Version });
                });

            migrationBuilder.CreateTable(
                name: "repositories",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Provider = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ProviderRepoId = table.Column<long>(type: "bigint", nullable: false),
                    Owner = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    FullName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Url = table.Column<string>(type: "text", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    IsPrivate = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultBranch = table.Column<string>(type: "text", nullable: false),
                    AcquisitionStatus = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    LastAcquiredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RowVersion = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_repositories", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "repository_snapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    CommitSha = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    BranchName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ArchiveObjectKey = table.Column<string>(type: "text", nullable: true),
                    ArchiveSizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    FileCount = table.Column<int>(type: "integer", nullable: false),
                    TotalSizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    AcquiredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AnalysisStatus = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    AnalysisCompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CandidatesFound = table.Column<int>(type: "integer", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_repository_snapshots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_repository_snapshots_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "repository_sources",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    DiscoveryType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ApiHunterRecordId = table.Column<Guid>(type: "uuid", nullable: true),
                    ApiHunterRepoRefId = table.Column<long>(type: "bigint", nullable: true),
                    DiscoveredViaQuery = table.Column<string>(type: "text", nullable: true),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_repository_sources", x => x.Id);
                    table.ForeignKey(
                        name: "FK_repository_sources_api_hunter_records_ApiHunterRecordId",
                        column: x => x.ApiHunterRecordId,
                        principalTable: "api_hunter_records",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_repository_sources_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "snapshot_files",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SnapshotId = table.Column<Guid>(type: "uuid", nullable: false),
                    FilePath = table.Column<string>(type: "text", nullable: false),
                    FileName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    FileExtension = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ContentHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    IsAnalyzed = table.Column<bool>(type: "boolean", nullable: false),
                    IsBinary = table.Column<bool>(type: "boolean", nullable: false),
                    IsSkipped = table.Column<bool>(type: "boolean", nullable: false),
                    SkipReason = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_snapshot_files", x => x.Id);
                    table.ForeignKey(
                        name: "FK_snapshot_files_repository_snapshots_SnapshotId",
                        column: x => x.SnapshotId,
                        principalTable: "repository_snapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "candidate_occurrences",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CandidateId = table.Column<Guid>(type: "uuid", nullable: false),
                    SnapshotFileId = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    DetectionRuleId = table.Column<string>(type: "character varying(100)", nullable: false),
                    RuleVersion = table.Column<int>(type: "integer", nullable: false),
                    OccurrenceFingerprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    LineNumber = table.Column<int>(type: "integer", nullable: false),
                    MatchStartIndex = table.Column<int>(type: "integer", nullable: false),
                    MatchLength = table.Column<int>(type: "integer", nullable: false),
                    LineContentRedacted = table.Column<string>(type: "text", nullable: true),
                    LineContentRawEncrypted = table.Column<string>(type: "text", nullable: true),
                    Confidence = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_candidate_occurrences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_candidate_occurrences_credential_candidates_CandidateId",
                        column: x => x.CandidateId,
                        principalTable: "credential_candidates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_candidate_occurrences_detection_rules_DetectionRuleId_RuleV~",
                        columns: x => new { x.DetectionRuleId, x.RuleVersion },
                        principalTable: "detection_rules",
                        principalColumns: new[] { "Id", "Version" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_candidate_occurrences_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_candidate_occurrences_snapshot_files_SnapshotFileId",
                        column: x => x.SnapshotFileId,
                        principalTable: "snapshot_files",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_analysis_jobs_LastHeartbeatAtUtc",
                table: "analysis_jobs",
                column: "LastHeartbeatAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_analysis_jobs_QueuedByUserId",
                table: "analysis_jobs",
                column: "QueuedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_analysis_jobs_Status_Priority_QueuedAtUtc",
                table: "analysis_jobs",
                columns: new[] { "Status", "Priority", "QueuedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_candidate_occurrences_CandidateId",
                table: "candidate_occurrences",
                column: "CandidateId");

            migrationBuilder.CreateIndex(
                name: "IX_candidate_occurrences_DetectionRuleId_RuleVersion",
                table: "candidate_occurrences",
                columns: new[] { "DetectionRuleId", "RuleVersion" });

            migrationBuilder.CreateIndex(
                name: "IX_candidate_occurrences_OccurrenceFingerprint",
                table: "candidate_occurrences",
                column: "OccurrenceFingerprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_candidate_occurrences_RepositoryId",
                table: "candidate_occurrences",
                column: "RepositoryId");

            migrationBuilder.CreateIndex(
                name: "IX_candidate_occurrences_SnapshotFileId",
                table: "candidate_occurrences",
                column: "SnapshotFileId");

            migrationBuilder.CreateIndex(
                name: "IX_credential_candidates_CredentialType",
                table: "credential_candidates",
                column: "CredentialType");

            migrationBuilder.CreateIndex(
                name: "IX_credential_candidates_ResolvedByUserId",
                table: "credential_candidates",
                column: "ResolvedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_credential_candidates_SecretFingerprint",
                table: "credential_candidates",
                column: "SecretFingerprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_credential_candidates_Status",
                table: "credential_candidates",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_repositories_AcquisitionStatus",
                table: "repositories",
                column: "AcquisitionStatus");

            migrationBuilder.CreateIndex(
                name: "IX_repositories_Owner_Name",
                table: "repositories",
                columns: new[] { "Owner", "Name" });

            migrationBuilder.CreateIndex(
                name: "IX_repositories_Provider_ProviderRepoId",
                table: "repositories",
                columns: new[] { "Provider", "ProviderRepoId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_repository_snapshots_AcquiredAtUtc",
                table: "repository_snapshots",
                column: "AcquiredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_repository_snapshots_AnalysisStatus",
                table: "repository_snapshots",
                column: "AnalysisStatus");

            migrationBuilder.CreateIndex(
                name: "IX_repository_snapshots_RepositoryId_CommitSha",
                table: "repository_snapshots",
                columns: new[] { "RepositoryId", "CommitSha" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_repository_sources_ApiHunterRecordId",
                table: "repository_sources",
                column: "ApiHunterRecordId");

            migrationBuilder.CreateIndex(
                name: "IX_repository_sources_RepositoryId",
                table: "repository_sources",
                column: "RepositoryId");

            migrationBuilder.CreateIndex(
                name: "IX_repository_sources_RepositoryId_ApiHunterRecordId_ApiHunter~",
                table: "repository_sources",
                columns: new[] { "RepositoryId", "ApiHunterRecordId", "ApiHunterRepoRefId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_snapshot_files_ContentHash",
                table: "snapshot_files",
                column: "ContentHash");

            migrationBuilder.CreateIndex(
                name: "IX_snapshot_files_SnapshotId",
                table: "snapshot_files",
                column: "SnapshotId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "analysis_jobs");

            migrationBuilder.DropTable(
                name: "candidate_occurrences");

            migrationBuilder.DropTable(
                name: "repository_sources");

            migrationBuilder.DropTable(
                name: "credential_candidates");

            migrationBuilder.DropTable(
                name: "detection_rules");

            migrationBuilder.DropTable(
                name: "snapshot_files");

            migrationBuilder.DropTable(
                name: "repository_snapshots");

            migrationBuilder.DropTable(
                name: "repositories");
        }
    }
}
