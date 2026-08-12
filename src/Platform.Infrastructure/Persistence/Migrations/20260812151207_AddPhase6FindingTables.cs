using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase6FindingTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "security_findings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    SnapshotId = table.Column<Guid>(type: "uuid", nullable: true),
                    FindingFingerprint = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    FindingType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Severity = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    Confidence = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    Status = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    Title = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false),
                    RiskScore = table.Column<int>(type: "integer", nullable: false),
                    RiskFactorBreakdownJson = table.Column<string>(type: "jsonb", nullable: false),
                    FirstObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ResolvedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ResolvedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ResolutionReason = table.Column<string>(type: "text", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_findings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_security_findings_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_security_findings_repository_snapshots_SnapshotId",
                        column: x => x.SnapshotId,
                        principalTable: "repository_snapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "security_finding_evidence",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    EvidenceType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    DiscoverySource = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    EvidenceFingerprint = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SnapshotId = table.Column<Guid>(type: "uuid", nullable: true),
                    SnapshotFileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CandidateId = table.Column<Guid>(type: "uuid", nullable: true),
                    ValidationResultId = table.Column<Guid>(type: "uuid", nullable: true),
                    IntelligenceNodeId = table.Column<Guid>(type: "uuid", nullable: true),
                    IntelligenceEdgeId = table.Column<Guid>(type: "uuid", nullable: true),
                    EvidenceReference = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    SafeEvidenceJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_finding_evidence", x => x.Id);
                    table.ForeignKey(
                        name: "FK_security_finding_evidence_security_findings_FindingId",
                        column: x => x.FindingId,
                        principalTable: "security_findings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_security_finding_evidence_FindingId_EvidenceFingerprint",
                table: "security_finding_evidence",
                columns: new[] { "FindingId", "EvidenceFingerprint" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_findings_FindingFingerprint",
                table: "security_findings",
                column: "FindingFingerprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_findings_RepositoryId_Status",
                table: "security_findings",
                columns: new[] { "RepositoryId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_security_findings_Severity_Confidence",
                table: "security_findings",
                columns: new[] { "Severity", "Confidence" });

            migrationBuilder.CreateIndex(
                name: "IX_security_findings_SnapshotId",
                table: "security_findings",
                column: "SnapshotId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "security_finding_evidence");

            migrationBuilder.DropTable(
                name: "security_findings");
        }
    }
}
