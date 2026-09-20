using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Phase 10 — Adds operational_incidents and ai_operational_diagnoses tables
    /// for autonomous incident detection, self-healing recovery, and AI-assisted root-cause diagnosis.
    /// </summary>
    public partial class AddOperationsIncidentAndDiagnosisTables : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ai_operational_diagnoses",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    IncidentId = table.Column<Guid>(type: "uuid", nullable: false),
                    AnalyzedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ProviderUsed = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RootCauseSummary = table.Column<string>(type: "text", nullable: false),
                    SuggestedRemediation = table.Column<string>(type: "text", nullable: false),
                    ConfidenceScore = table.Column<double>(type: "double precision", nullable: false),
                    IsDeterministicFallback = table.Column<bool>(type: "boolean", nullable: false),
                    SanitizedPrompt = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ai_operational_diagnoses", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "operational_incidents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    Severity = table.Column<int>(type: "integer", nullable: false),
                    Category = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    Title = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Fingerprint = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    FirstObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    OccurrenceCount = table.Column<int>(type: "integer", nullable: false),
                    DetailsJson = table.Column<string>(type: "text", nullable: true),
                    ResolutionNotes = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    MitigationActionTaken = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    AiDiagnosisId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_operational_incidents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_operational_incidents_ai_operational_diagnoses_AiDiagnosisId",
                        column: x => x.AiDiagnosisId,
                        principalTable: "ai_operational_diagnoses",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ai_operational_diagnoses_IncidentId",
                table: "ai_operational_diagnoses",
                column: "IncidentId");

            migrationBuilder.CreateIndex(
                name: "IX_operational_incidents_AiDiagnosisId",
                table: "operational_incidents",
                column: "AiDiagnosisId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_operational_incidents_Fingerprint_LastObservedAtUtc",
                table: "operational_incidents",
                columns: new[] { "Fingerprint", "LastObservedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_operational_incidents_TenantId_Status",
                table: "operational_incidents",
                columns: new[] { "TenantId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_operational_incidents_Severity",
                table: "operational_incidents",
                column: "Severity");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "operational_incidents");
            migrationBuilder.DropTable(name: "ai_operational_diagnoses");
        }
    }
}
