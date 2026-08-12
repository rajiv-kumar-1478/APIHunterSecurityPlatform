using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase5ValidationTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "FirstObservedAtUtc",
                table: "security_intelligence_nodes",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "LastObservedAtUtc",
                table: "security_intelligence_nodes",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "FirstObservedAtUtc",
                table: "security_intelligence_edges",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "LastObservedAtUtc",
                table: "security_intelligence_edges",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "CooldownUntilUtc",
                table: "ai_provider_configs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ClaimToken",
                table: "ai_investigation_jobs",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<DateTime>(
                name: "LastHeartbeatAtUtc",
                table: "ai_investigation_jobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WorkerId",
                table: "ai_investigation_jobs",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Fingerprint",
                table: "ai_investigation_evidences",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "credential_validation_results",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CandidateId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Confidence = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    ValidatorVersion = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    PolicyVersion = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    ResponseClassification = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    SafeEvidenceJson = table.Column<string>(type: "jsonb", nullable: false),
                    LatencyMs = table.Column<long>(type: "bigint", nullable: false),
                    HttpStatusCode = table.Column<int>(type: "integer", nullable: true),
                    RetryAfterUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ValidationAttemptNumber = table.Column<int>(type: "integer", nullable: false),
                    AnalysisJobId = table.Column<Guid>(type: "uuid", nullable: true),
                    ValidatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_credential_validation_results", x => x.Id);
                    table.ForeignKey(
                        name: "FK_credential_validation_results_analysis_jobs_AnalysisJobId",
                        column: x => x.AnalysisJobId,
                        principalTable: "analysis_jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_credential_validation_results_credential_candidates_Candida~",
                        column: x => x.CandidateId,
                        principalTable: "credential_candidates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_jobs_ClaimToken",
                table: "ai_investigation_jobs",
                column: "ClaimToken");

            migrationBuilder.CreateIndex(
                name: "IX_ai_investigation_evidences_Fingerprint",
                table: "ai_investigation_evidences",
                column: "Fingerprint");

            migrationBuilder.CreateIndex(
                name: "IX_credential_validation_results_AnalysisJobId",
                table: "credential_validation_results",
                column: "AnalysisJobId");

            migrationBuilder.CreateIndex(
                name: "IX_credential_validation_results_CandidateId_ValidatedAtUtc",
                table: "credential_validation_results",
                columns: new[] { "CandidateId", "ValidatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_credential_validation_results_Status_ProviderName",
                table: "credential_validation_results",
                columns: new[] { "Status", "ProviderName" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "credential_validation_results");

            migrationBuilder.DropIndex(
                name: "IX_ai_investigation_jobs_ClaimToken",
                table: "ai_investigation_jobs");

            migrationBuilder.DropIndex(
                name: "IX_ai_investigation_evidences_Fingerprint",
                table: "ai_investigation_evidences");

            migrationBuilder.DropColumn(
                name: "FirstObservedAtUtc",
                table: "security_intelligence_nodes");

            migrationBuilder.DropColumn(
                name: "LastObservedAtUtc",
                table: "security_intelligence_nodes");

            migrationBuilder.DropColumn(
                name: "FirstObservedAtUtc",
                table: "security_intelligence_edges");

            migrationBuilder.DropColumn(
                name: "LastObservedAtUtc",
                table: "security_intelligence_edges");

            migrationBuilder.DropColumn(
                name: "CooldownUntilUtc",
                table: "ai_provider_configs");

            migrationBuilder.DropColumn(
                name: "ClaimToken",
                table: "ai_investigation_jobs");

            migrationBuilder.DropColumn(
                name: "LastHeartbeatAtUtc",
                table: "ai_investigation_jobs");

            migrationBuilder.DropColumn(
                name: "WorkerId",
                table: "ai_investigation_jobs");

            migrationBuilder.DropColumn(
                name: "Fingerprint",
                table: "ai_investigation_evidences");
        }
    }
}
