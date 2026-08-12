using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase4Tables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ai_investigation_jobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    SnapshotId = table.Column<Guid>(type: "uuid", nullable: false),
                    CurrentStage = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    CompletedStagesCount = table.Column<int>(type: "integer", nullable: false),
                    ActiveProviderName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ActiveModelName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    TotalPromptTokens = table.Column<int>(type: "integer", nullable: false),
                    TotalCompletionTokens = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ErrorMessage = table.Column<string>(type: "text", nullable: true),
                    QueuedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ai_investigation_jobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ai_investigation_jobs_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ai_investigation_jobs_repository_snapshots_SnapshotId",
                        column: x => x.SnapshotId,
                        principalTable: "repository_snapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ai_provider_configs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    ModelName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Priority = table.Column<int>(type: "integer", nullable: false),
                    EncryptedApiKey = table.Column<string>(type: "text", nullable: false),
                    CapabilitiesJson = table.Column<string>(type: "jsonb", nullable: false),
                    HealthStatus = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    LastSuccessAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastFailureAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastErrorReason = table.Column<string>(type: "text", nullable: true),
                    RateLimitResetAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RemainingQuota = table.Column<int>(type: "integer", nullable: false),
                    TotalCallsCount = table.Column<long>(type: "bigint", nullable: false),
                    FailedCallsCount = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ai_provider_configs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "repository_risk_scores",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    Score = table.Column<int>(type: "integer", nullable: false),
                    Severity = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    AlgorithmVersion = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    FactorBreakdownJson = table.Column<string>(type: "jsonb", nullable: false),
                    CalculatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_repository_risk_scores", x => x.Id);
                    table.ForeignKey(
                        name: "FK_repository_risk_scores_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "security_intelligence_nodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    NodeType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Label = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    RelatedEntityId = table.Column<Guid>(type: "uuid", nullable: true),
                    MetadataJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_intelligence_nodes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ai_investigation_checkpoints",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    InvestigationJobId = table.Column<Guid>(type: "uuid", nullable: false),
                    StageType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    CursorPosition = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    DurableResultJson = table.Column<string>(type: "jsonb", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ai_investigation_checkpoints", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ai_investigation_checkpoints_ai_investigation_jobs_Investig~",
                        column: x => x.InvestigationJobId,
                        principalTable: "ai_investigation_jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ai_investigation_evidences",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    InvestigationId = table.Column<Guid>(type: "uuid", nullable: true),
                    SnapshotId = table.Column<Guid>(type: "uuid", nullable: false),
                    SnapshotFileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CandidateId = table.Column<Guid>(type: "uuid", nullable: true),
                    EvidenceType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    FilePath = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    StartLine = table.Column<int>(type: "integer", nullable: false),
                    EndLine = table.Column<int>(type: "integer", nullable: false),
                    Confidence = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    Source = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    EvidenceJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ai_investigation_evidences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ai_investigation_evidences_ai_investigation_jobs_Investigat~",
                        column: x => x.InvestigationId,
                        principalTable: "ai_investigation_jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_ai_investigation_evidences_credential_candidates_CandidateId",
                        column: x => x.CandidateId,
                        principalTable: "credential_candidates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_ai_investigation_evidences_repository_snapshots_SnapshotId",
                        column: x => x.SnapshotId,
                        principalTable: "repository_snapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_ai_investigation_evidences_snapshot_files_SnapshotFileId",
                        column: x => x.SnapshotFileId,
                        principalTable: "snapshot_files",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "security_intelligence_edges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SourceNodeId = table.Column<Guid>(type: "uuid", nullable: false),
                    TargetNodeId = table.Column<Guid>(type: "uuid", nullable: false),
                    EdgeType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    DiscoverySource = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Confidence = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    EvidenceReference = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_intelligence_edges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_security_intelligence_edges_security_intelligence_nodes_Sou~",
                        column: x => x.SourceNodeId,
                        principalTable: "security_intelligence_nodes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_security_intelligence_edges_security_intelligence_nodes_Tar~",
                        column: x => x.TargetNodeId,
                        principalTable: "security_intelligence_nodes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_checkpoints_InvestigationJobId_StageType",
                table: "ai_investigation_checkpoints",
                columns: new[] { "InvestigationJobId", "StageType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_evidences_CandidateId",
                table: "ai_investigation_evidences",
                column: "CandidateId");

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_evidences_InvestigationId",
                table: "ai_investigation_evidences",
                column: "InvestigationId");

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_evidences_SnapshotFileId",
                table: "ai_investigation_evidences",
                column: "SnapshotFileId");

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_evidences_SnapshotId",
                table: "ai_investigation_evidences",
                column: "SnapshotId");

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_jobs_RepositoryId",
                table: "ai_investigation_jobs",
                column: "RepositoryId");

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_jobs_SnapshotId",
                table: "ai_investigation_jobs",
                column: "SnapshotId");

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_jobs_Status_CurrentStage_QueuedAtUtc",
                table: "ai_investigation_jobs",
                columns: new[] { "Status", "CurrentStage", "QueuedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_ai_provider_configs_IsEnabled_Priority_HealthStatus",
                table: "ai_provider_configs",
                columns: new[] { "IsEnabled", "Priority", "HealthStatus" });

            migrationBuilder.CreateIndex(
                name: "IX_ai_provider_configs_ProviderName_ModelName",
                table: "ai_provider_configs",
                columns: new[] { "ProviderName", "ModelName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_repository_risk_scores_RepositoryId_CalculatedAtUtc",
                table: "repository_risk_scores",
                columns: new[] { "RepositoryId", "CalculatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_repository_risk_scores_Severity",
                table: "repository_risk_scores",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_security_intelligence_edges_SourceNodeId",
                table: "security_intelligence_edges",
                column: "SourceNodeId");

            migrationBuilder.CreateIndex(
                name: "IX_security_intelligence_edges_SourceNodeId_TargetNodeId_EdgeT~",
                table: "security_intelligence_edges",
                columns: new[] { "SourceNodeId", "TargetNodeId", "EdgeType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_intelligence_edges_TargetNodeId",
                table: "security_intelligence_edges",
                column: "TargetNodeId");

            migrationBuilder.CreateIndex(
                name: "IX_security_intelligence_nodes_NodeType",
                table: "security_intelligence_nodes",
                column: "NodeType");

            migrationBuilder.CreateIndex(
                name: "IX_security_intelligence_nodes_NodeType_Name",
                table: "security_intelligence_nodes",
                columns: new[] { "NodeType", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_intelligence_nodes_RelatedEntityId",
                table: "security_intelligence_nodes",
                column: "RelatedEntityId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ai_investigation_checkpoints");

            migrationBuilder.DropTable(
                name: "ai_investigation_evidences");

            migrationBuilder.DropTable(
                name: "ai_provider_configs");

            migrationBuilder.DropTable(
                name: "repository_risk_scores");

            migrationBuilder.DropTable(
                name: "security_intelligence_edges");

            migrationBuilder.DropTable(
                name: "ai_investigation_jobs");

            migrationBuilder.DropTable(
                name: "security_intelligence_nodes");
        }
    }
}
