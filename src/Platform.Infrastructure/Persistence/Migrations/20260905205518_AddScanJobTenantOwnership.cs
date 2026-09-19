using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Reconciles scanner persistence after the hand-authored Phase 8/9 migrations and
    /// establishes durable tenant ownership independently from the optional requesting actor.
    ///
    /// DEPLOYMENT BOUNDARY: this migration is NOT rolling-safe for pre-tenant scan-job
    /// binaries. It makes security_scan_jobs."TenantId" required with no insert default and
    /// makes "RequestedByUserId" nullable, so an older writer omits required ownership and an
    /// older reader cannot materialize scheduler rows that have a null requester. Stop and
    /// drain every pre-tenant API, scheduler, and worker instance before applying it. The
    /// later token bridges in 20260906024820_FixPostgreSqlRowVersionTokens permit overlap
    /// only among binaries already compatible with this tenant schema.
    /// </summary>
    public partial class AddScanJobTenantOwnership : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Current scanner-tool fields that were introduced after the artifact migration.
            migrationBuilder.AddColumn<string>(
                name: "ArtifactFormat",
                table: "security_scan_tools",
                type: "character varying(50)",
                maxLength: 50,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ArtifactUrl",
                table: "security_scan_tools",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CapabilityProbeCommand",
                table: "security_scan_tools",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CapabilityProbeExpectedKeyword",
                table: "security_scan_tools",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ContainerImageRepository",
                table: "security_scan_tools",
                type: "text",
                nullable: true);

            // Scheduler-created jobs have no human actor. The FK remains optional/Restrict.
            migrationBuilder.AlterColumn<Guid>(
                name: "RequestedByUserId",
                table: "security_scan_jobs",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AddColumn<string>(
                name: "CurrentPhase",
                table: "security_scan_jobs",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CurrentTool",
                table: "security_scan_jobs",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExecutionReceiptJson",
                table: "security_scan_jobs",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ProgressPercentage",
                table: "security_scan_jobs",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<Guid>(
                name: "RetryOfJobId",
                table: "security_scan_jobs",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "TotalFindingsCount",
                table: "security_scan_jobs",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            // Add tenant ownership as nullable first. Never manufacture Guid.Empty ownership.
            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "security_scan_jobs",
                type: "uuid",
                nullable: true);

            // Campaign ownership is authoritative for campaign jobs.
            migrationBuilder.Sql(
                """
                UPDATE security_scan_jobs AS job
                SET "TenantId" = campaign."TenantId"
                FROM scan_campaigns AS campaign
                WHERE job."TenantId" IS NULL
                  AND job."CampaignId" = campaign."Id"
                  AND campaign."TenantId" <> '00000000-0000-0000-0000-000000000000'::uuid;
                """);

            // Before durable TenantId existed, legacy manual jobs used RequestedByUserId as
            // their ownership discriminator. Preserve that established ownership semantics.
            migrationBuilder.Sql(
                """
                UPDATE security_scan_jobs
                SET "TenantId" = "RequestedByUserId"
                WHERE "TenantId" IS NULL
                  AND "RequestedByUserId" IS NOT NULL
                  AND "RequestedByUserId" <> '00000000-0000-0000-0000-000000000000'::uuid;
                """);

            // Abort instead of deleting jobs or silently assigning them to an empty tenant.
            migrationBuilder.Sql(
                """
                DO $tenant_guard$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM security_scan_jobs
                        WHERE "TenantId" IS NULL
                           OR "TenantId" = '00000000-0000-0000-0000-000000000000'::uuid
                    ) THEN
                        RAISE EXCEPTION
                            'Cannot require security_scan_jobs.TenantId: unresolved or empty tenant ownership remains';
                    END IF;
                END
                $tenant_guard$;
                """);

            // Guid.Empty never identifies a real user; system/campaign jobs use null.
            migrationBuilder.Sql(
                """
                UPDATE security_scan_jobs
                SET "RequestedByUserId" = NULL
                WHERE "RequestedByUserId" = '00000000-0000-0000-0000-000000000000'::uuid;
                """);

            migrationBuilder.AlterColumn<Guid>(
                name: "TenantId",
                table: "security_scan_jobs",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            // Scanner observation and immutable execution-audit tables were part of the
            // current model but had never been represented in a physical migration.
            migrationBuilder.CreateTable(
                name: "scan_finding_observations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    ScanJobId = table.Column<Guid>(type: "uuid", nullable: false),
                    ObservedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    WasObserved = table.Column<bool>(type: "boolean", nullable: false),
                    FullCoverageConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                    ToolCoverageHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scan_finding_observations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_scan_finding_observations_security_findings_FindingId",
                        column: x => x.FindingId,
                        principalTable: "security_findings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_scan_finding_observations_security_scan_jobs_ScanJobId",
                        column: x => x.ScanJobId,
                        principalTable: "security_scan_jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "scan_plan_audits",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ScanJobId = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    TargetUrl = table.Column<string>(type: "text", nullable: false),
                    TargetKind = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Profile = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    PlanHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    PlannerVersion = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    RegistrySnapshotHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ExecutionSequenceJson = table.Column<string>(type: "text", nullable: false),
                    SelectionReasonsJson = table.Column<string>(type: "text", nullable: false),
                    RuleSetVersionsJson = table.Column<string>(type: "text", nullable: false),
                    ToolManifestSnapshotsJson = table.Column<string>(type: "text", nullable: false),
                    CapabilitySnapshotJson = table.Column<string>(type: "text", nullable: false),
                    SelectionPolicySnapshotJson = table.Column<string>(type: "text", nullable: false),
                    PreviousAuditHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    RecordHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    PlannedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scan_plan_audits", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "scan_tool_invocations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ScanJobId = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    ToolKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ToolVersion = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ContainerImageDigest = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    RuleSetVersion = table.Column<string>(type: "text", nullable: false),
                    PlanHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    RegistrySnapshotHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ExecutionPhase = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ExitCode = table.Column<int>(type: "integer", nullable: false),
                    DurationMs = table.Column<long>(type: "bigint", nullable: false),
                    CandidateCount = table.Column<int>(type: "integer", nullable: false),
                    CoverageJson = table.Column<string>(type: "text", nullable: false),
                    ErrorMessage = table.Column<string>(type: "text", nullable: true),
                    StartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scan_tool_invocations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_TenantId",
                table: "security_scan_jobs",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_TenantId_Status_CreatedAtUtc",
                table: "security_scan_jobs",
                columns: new[] { "TenantId", "Status", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_scan_finding_observations_FindingId_ObservedAtUtc",
                table: "scan_finding_observations",
                columns: new[] { "FindingId", "ObservedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_scan_finding_observations_FindingId_ScanJobId",
                table: "scan_finding_observations",
                columns: new[] { "FindingId", "ScanJobId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_scan_finding_observations_ScanJobId",
                table: "scan_finding_observations",
                column: "ScanJobId");

            migrationBuilder.CreateIndex(
                name: "IX_scan_plan_audits_PlanHash",
                table: "scan_plan_audits",
                column: "PlanHash");

            migrationBuilder.CreateIndex(
                name: "IX_scan_plan_audits_ScanJobId",
                table: "scan_plan_audits",
                column: "ScanJobId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_scan_plan_audits_TenantId_PlannedAtUtc",
                table: "scan_plan_audits",
                columns: new[] { "TenantId", "PlannedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_scan_tool_invocations_ScanJobId_ToolKey",
                table: "scan_tool_invocations",
                columns: new[] { "ScanJobId", "ToolKey" });

            migrationBuilder.CreateIndex(
                name: "IX_scan_tool_invocations_TenantId_StartedAtUtc",
                table: "scan_tool_invocations",
                columns: new[] { "TenantId", "StartedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Reverting to a required requester would require inventing a user for system jobs.
            // Refuse that lossy rollback and require an operator-owned data remediation instead.
            migrationBuilder.Sql(
                """
                DO $requester_guard$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM security_scan_jobs
                        WHERE "RequestedByUserId" IS NULL
                    ) THEN
                        RAISE EXCEPTION
                            'Cannot make security_scan_jobs.RequestedByUserId required while system-created jobs exist';
                    END IF;
                END
                $requester_guard$;
                """);

            migrationBuilder.DropTable(
                name: "scan_finding_observations");

            migrationBuilder.DropTable(
                name: "scan_plan_audits");

            migrationBuilder.DropTable(
                name: "scan_tool_invocations");

            migrationBuilder.DropIndex(
                name: "IX_security_scan_jobs_TenantId",
                table: "security_scan_jobs");

            migrationBuilder.DropIndex(
                name: "IX_security_scan_jobs_TenantId_Status_CreatedAtUtc",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(
                name: "ArtifactFormat",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "ArtifactUrl",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "CapabilityProbeCommand",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "CapabilityProbeExpectedKeyword",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "ContainerImageRepository",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "CurrentPhase",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(
                name: "CurrentTool",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(
                name: "ExecutionReceiptJson",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(
                name: "ProgressPercentage",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(
                name: "RetryOfJobId",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(
                name: "TotalFindingsCount",
                table: "security_scan_jobs");

            migrationBuilder.AlterColumn<Guid>(
                name: "RequestedByUserId",
                table: "security_scan_jobs",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);
        }
    }
}
