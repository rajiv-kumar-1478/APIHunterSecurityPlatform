using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase7RemediationExecutionTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "remediation_executions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RemediationActionId = table.Column<Guid>(type: "uuid", nullable: false),
                    ActionVersion = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ProviderKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ProviderResourceReference = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    StartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExecutionDurationMs = table.Column<long>(type: "bigint", nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    FailureCode = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    FailureReason = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    ProviderOperationId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    PreExecutionRiskScore = table.Column<int>(type: "integer", nullable: true),
                    PostExecutionRiskScore = table.Column<int>(type: "integer", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_remediation_executions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_remediation_executions_remediation_actions_RemediationActio~",
                        column: x => x.RemediationActionId,
                        principalTable: "remediation_actions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_remediation_executions_RemediationActionId_ActionVersion",
                table: "remediation_executions",
                columns: new[] { "RemediationActionId", "ActionVersion" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_remediation_executions_StartedAtUtc",
                table: "remediation_executions",
                column: "StartedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_remediation_executions_Status",
                table: "remediation_executions",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "remediation_executions");
        }
    }
}
