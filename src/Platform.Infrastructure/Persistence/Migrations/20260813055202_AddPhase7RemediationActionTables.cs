using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase7RemediationActionTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "LifecycleVersion",
                table: "security_findings",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "ProcessedForFindingAtUtc",
                table: "credential_validation_results",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ProcessingClaimToken",
                table: "credential_validation_results",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ProcessingClaimedAtUtc",
                table: "credential_validation_results",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "remediation_actions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    ActionType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Title = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    ActionFingerprint = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    RequiresApproval = table.Column<bool>(type: "boolean", nullable: false),
                    ProposedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ApprovedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RejectedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    RejectedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ApprovalReason = table.Column<string>(type: "text", nullable: true),
                    RejectionReason = table.Column<string>(type: "text", nullable: true),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExecutionStartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExecutionCompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ProviderKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    ProviderResourceReference = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    PreExecutionRiskScore = table.Column<int>(type: "integer", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remediation_actions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_remediation_actions_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_remediation_actions_security_findings_FindingId",
                        column: x => x.FindingId,
                        principalTable: "security_findings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_remediation_actions_users_ApprovedByUserId",
                        column: x => x.ApprovedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_remediation_actions_users_ProposedByUserId",
                        column: x => x.ProposedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_remediation_actions_users_RejectedByUserId",
                        column: x => x.RejectedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "security_alert_logs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<Guid>(type: "uuid", nullable: true),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: true),
                    CandidateId = table.Column<Guid>(type: "uuid", nullable: true),
                    FindingFingerprint = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    AlertReason = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    AlertFingerprint = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Severity = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    RiskScore = table.Column<int>(type: "integer", nullable: false),
                    Recipient = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    SentAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ClaimToken = table.Column<Guid>(type: "uuid", nullable: true),
                    ClaimedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_alert_logs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "security_finding_status_histories",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    FromStatus = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    ToStatus = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    ChangedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    MetadataJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_finding_status_histories", x => x.Id);
                    table.ForeignKey(
                        name: "FK_security_finding_status_histories_security_findings_Finding~",
                        column: x => x.FindingId,
                        principalTable: "security_findings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_security_finding_status_histories_users_ChangedByUserId",
                        column: x => x.ChangedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "remediation_action_histories",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RemediationActionId = table.Column<Guid>(type: "uuid", nullable: false),
                    FromStatus = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ToStatus = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ChangedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    MetadataJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remediation_action_histories", x => x.Id);
                    table.ForeignKey(
                        name: "FK_remediation_action_histories_remediation_actions_Remediatio~",
                        column: x => x.RemediationActionId,
                        principalTable: "remediation_actions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_remediation_action_histories_users_ChangedByUserId",
                        column: x => x.ChangedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_security_findings_ResolvedByUserId",
                table: "security_findings",
                column: "ResolvedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_credential_validation_results_ProcessedForFindingAtUtc_Vali~",
                table: "credential_validation_results",
                columns: new[] { "ProcessedForFindingAtUtc", "ValidatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_remediation_action_histories_ChangedByUserId",
                table: "remediation_action_histories",
                column: "ChangedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_action_histories_CreatedAtUtc",
                table: "remediation_action_histories",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_action_histories_RemediationActionId",
                table: "remediation_action_histories",
                column: "RemediationActionId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_ActionFingerprint",
                table: "remediation_actions",
                column: "ActionFingerprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_ApprovedByUserId",
                table: "remediation_actions",
                column: "ApprovedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_CreatedAtUtc",
                table: "remediation_actions",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_ExpiresAtUtc",
                table: "remediation_actions",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_FindingId",
                table: "remediation_actions",
                column: "FindingId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_ProposedByUserId",
                table: "remediation_actions",
                column: "ProposedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_RejectedByUserId",
                table: "remediation_actions",
                column: "RejectedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_RepositoryId",
                table: "remediation_actions",
                column: "RepositoryId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_actions_Status",
                table: "remediation_actions",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_security_alert_logs_AlertFingerprint_SentAtUtc",
                table: "security_alert_logs",
                columns: new[] { "AlertFingerprint", "SentAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_security_alert_logs_FindingFingerprint",
                table: "security_alert_logs",
                column: "FindingFingerprint");

            migrationBuilder.CreateIndex(
                name: "IX_security_finding_status_histories_ChangedByUserId",
                table: "security_finding_status_histories",
                column: "ChangedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_security_finding_status_histories_CreatedAtUtc",
                table: "security_finding_status_histories",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_security_finding_status_histories_FindingId",
                table: "security_finding_status_histories",
                column: "FindingId");

            migrationBuilder.AddForeignKey(
                name: "FK_security_findings_users_ResolvedByUserId",
                table: "security_findings",
                column: "ResolvedByUserId",
                principalTable: "users",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_security_findings_users_ResolvedByUserId",
                table: "security_findings");

            migrationBuilder.DropTable(
                name: "remediation_action_histories");

            migrationBuilder.DropTable(
                name: "security_alert_logs");

            migrationBuilder.DropTable(
                name: "security_finding_status_histories");

            migrationBuilder.DropTable(
                name: "remediation_actions");

            migrationBuilder.DropIndex(
                name: "IX_security_findings_ResolvedByUserId",
                table: "security_findings");

            migrationBuilder.DropIndex(
                name: "IX_credential_validation_results_ProcessedForFindingAtUtc_Vali~",
                table: "credential_validation_results");

            migrationBuilder.DropColumn(
                name: "LifecycleVersion",
                table: "security_findings");

            migrationBuilder.DropColumn(
                name: "ProcessedForFindingAtUtc",
                table: "credential_validation_results");

            migrationBuilder.DropColumn(
                name: "ProcessingClaimToken",
                table: "credential_validation_results");

            migrationBuilder.DropColumn(
                name: "ProcessingClaimedAtUtc",
                table: "credential_validation_results");
        }
    }
}
