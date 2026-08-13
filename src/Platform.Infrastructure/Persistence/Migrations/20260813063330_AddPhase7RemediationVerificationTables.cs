using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase7RemediationVerificationTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "VerificationClaimToken",
                table: "remediation_actions",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "VerificationClaimedAtUtc",
                table: "remediation_actions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "remediation_verifications",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RemediationActionId = table.Column<Guid>(type: "uuid", nullable: false),
                    RemediationExecutionId = table.Column<Guid>(type: "uuid", nullable: true),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    VerifiedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PreExecutionRiskScore = table.Column<int>(type: "integer", nullable: false),
                    PostExecutionRiskScore = table.Column<int>(type: "integer", nullable: false),
                    RiskDelta = table.Column<int>(type: "integer", nullable: false),
                    ValidationResultStatus = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    VerificationDetailsJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remediation_verifications", x => x.Id);
                    table.ForeignKey(
                        name: "FK_remediation_verifications_remediation_actions_RemediationAc~",
                        column: x => x.RemediationActionId,
                        principalTable: "remediation_actions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_remediation_verifications_remediation_executions_Remediatio~",
                        column: x => x.RemediationExecutionId,
                        principalTable: "remediation_executions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_remediation_verifications_RemediationActionId",
                table: "remediation_verifications",
                column: "RemediationActionId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_remediation_verifications_RemediationExecutionId",
                table: "remediation_verifications",
                column: "RemediationExecutionId");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_verifications_Status",
                table: "remediation_verifications",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "remediation_verifications");

            migrationBuilder.DropColumn(
                name: "VerificationClaimToken",
                table: "remediation_actions");

            migrationBuilder.DropColumn(
                name: "VerificationClaimedAtUtc",
                table: "remediation_actions");
        }
    }
}
