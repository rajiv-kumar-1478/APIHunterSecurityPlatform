using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Phase 9 — Campaign Scheduler Tables and Phase 9.2 Concurrency Hardening.
    ///
    /// Creates:
    ///   - scan_campaigns table with ScheduleVersion optimistic concurrency token
    ///   - campaign_execution_audit_logs table
    ///
    /// Adds to security_scan_jobs:
    ///   - CampaignId (FK to scan_campaigns)
    ///   - TriggeredBy (Scheduler / ManualRunNow / CampaignRunNow)
    ///   - JobVersion (optimistic concurrency token for recovery race protection)
    ///   - WorkerInstanceId (which worker instance owns the running job)
    ///   - LastHeartbeatUtc (periodic liveness timestamp; recovery uses staleness to detect stuck jobs)
    ///   - CampaignOccurrenceKey (SHA256 idempotency key; 64-char hex)
    ///
    /// Idempotency gate:
    ///   IX_security_scan_jobs_campaign_occurrence_key UNIQUE partial index
    ///   on (campaign_id, campaign_occurrence_key) WHERE campaign_occurrence_key IS NOT NULL.
    ///   Enforces at the database level that a scheduled occurrence produces at most one SecurityScanJob,
    ///   even when the scheduler retries after an ambiguous network failure.
    /// </summary>
    public partial class AddPhase9CampaignScheduler : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // =====================================================================
            // scan_campaigns
            // =====================================================================
            migrationBuilder.CreateTable(
                name: "scan_campaigns",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    SecurityTargetId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ScanProfile = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ScheduleType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    CronExpression = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    IntervalDuration = table.Column<TimeSpan>(type: "interval", nullable: true),
                    TimeZoneId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ConcurrencyPolicy = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),

                    // Phase 9.2: Optimistic concurrency token for scheduler dispatch.
                    // EF Core includes this in UPDATE WHERE clause; concurrent schedulers race safely.
                    ScheduleVersion = table.Column<long>(type: "bigint", nullable: false, defaultValue: 1L),

                    NextRunUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastRunUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastScanJobId = table.Column<Guid>(type: "uuid", nullable: true),
                    TotalRunsCount = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    ConsecutiveFailuresCount = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    MaxConsecutiveFailures = table.Column<int>(type: "integer", nullable: false, defaultValue: 5),
                    AutoPauseOnConsecutiveFailures = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    LastCampaignOccurrenceKey = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scan_campaigns", x => x.Id);
                    table.ForeignKey(
                        name: "FK_scan_campaigns_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_scan_campaigns_security_targets_SecurityTargetId",
                        column: x => x.SecurityTargetId,
                        principalTable: "security_targets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            // =====================================================================
            // campaign_execution_audit_logs
            // =====================================================================
            migrationBuilder.CreateTable(
                name: "campaign_execution_audit_logs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CampaignId = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    Decision = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    TriggerSource = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ScheduleVersion = table.Column<long>(type: "bigint", nullable: false),
                    EvaluatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    DispatchedScanJobId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    MetadataJson = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_campaign_execution_audit_logs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_campaign_execution_audit_logs_scan_campaigns_CampaignId",
                        column: x => x.CampaignId,
                        principalTable: "scan_campaigns",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            // =====================================================================
            // Phase 9.2 columns on security_scan_jobs
            // =====================================================================
            migrationBuilder.AddColumn<Guid>(
                name: "CampaignId",
                table: "security_scan_jobs",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TriggeredBy",
                table: "security_scan_jobs",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                defaultValue: "Manual");

            // JobVersion: optimistic concurrency token for recovery race.
            // Live worker heartbeat increments this; recovery UPDATE WHERE JobVersion = @expected
            // causes DbUpdateConcurrencyException if the worker updated first.
            migrationBuilder.AddColumn<int>(
                name: "JobVersion",
                table: "security_scan_jobs",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<string>(
                name: "WorkerInstanceId",
                table: "security_scan_jobs",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastHeartbeatUtc",
                table: "security_scan_jobs",
                type: "timestamp with time zone",
                nullable: true);

            // CampaignOccurrenceKey: 64-char lowercase hex SHA256 idempotency key.
            // SHA256("v1\n" + CampaignId:D + "\n" + ScheduledOccurrenceUtc:O + "\n" + ScheduleVersion)
            migrationBuilder.AddColumn<string>(
                name: "CampaignOccurrenceKey",
                table: "security_scan_jobs",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            // =====================================================================
            // Indexes — scan_campaigns
            // =====================================================================
            migrationBuilder.CreateIndex(
                name: "IX_scan_campaigns_TenantId_Status",
                table: "scan_campaigns",
                columns: new[] { "TenantId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_scan_campaigns_Status_NextRunUtc",
                table: "scan_campaigns",
                columns: new[] { "Status", "NextRunUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_scan_campaigns_RepositoryId",
                table: "scan_campaigns",
                column: "RepositoryId");

            migrationBuilder.CreateIndex(
                name: "IX_scan_campaigns_SecurityTargetId",
                table: "scan_campaigns",
                column: "SecurityTargetId");

            // =====================================================================
            // Indexes — campaign_execution_audit_logs
            // =====================================================================
            migrationBuilder.CreateIndex(
                name: "IX_campaign_execution_audit_logs_CampaignId_EvaluatedAtUtc",
                table: "campaign_execution_audit_logs",
                columns: new[] { "CampaignId", "EvaluatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_campaign_execution_audit_logs_TenantId_EvaluatedAtUtc",
                table: "campaign_execution_audit_logs",
                columns: new[] { "TenantId", "EvaluatedAtUtc" });

            // =====================================================================
            // Indexes — security_scan_jobs (Phase 9.2 additions)
            // =====================================================================
            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_CampaignId",
                table: "security_scan_jobs",
                column: "CampaignId");

            // Phase 9.2 HARD GATE: The unique partial index is the database-level idempotency
            // invariant. The scheduler application checks the key before dispatching, but this
            // constraint is the final line of defense when a scheduler retries after a commit
            // whose success was ambiguous (network partition after DB write, before ACK).
            migrationBuilder.Sql(@"
                CREATE UNIQUE INDEX IX_security_scan_jobs_campaign_occurrence_key
                ON security_scan_jobs (""CampaignId"", ""CampaignOccurrenceKey"")
                WHERE ""CampaignOccurrenceKey"" IS NOT NULL;
            ");

            // FK from security_scan_jobs.CampaignId → scan_campaigns.Id
            migrationBuilder.AddForeignKey(
                name: "FK_security_scan_jobs_scan_campaigns_CampaignId",
                table: "security_scan_jobs",
                column: "CampaignId",
                principalTable: "scan_campaigns",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_security_scan_jobs_scan_campaigns_CampaignId",
                table: "security_scan_jobs");

            migrationBuilder.Sql(@"
                DROP INDEX IF EXISTS IX_security_scan_jobs_campaign_occurrence_key;
            ");

            migrationBuilder.DropIndex(
                name: "IX_security_scan_jobs_CampaignId",
                table: "security_scan_jobs");

            migrationBuilder.DropColumn(name: "CampaignId", table: "security_scan_jobs");
            migrationBuilder.DropColumn(name: "TriggeredBy", table: "security_scan_jobs");
            migrationBuilder.DropColumn(name: "JobVersion", table: "security_scan_jobs");
            migrationBuilder.DropColumn(name: "WorkerInstanceId", table: "security_scan_jobs");
            migrationBuilder.DropColumn(name: "LastHeartbeatUtc", table: "security_scan_jobs");
            migrationBuilder.DropColumn(name: "CampaignOccurrenceKey", table: "security_scan_jobs");

            migrationBuilder.DropTable(name: "campaign_execution_audit_logs");
            migrationBuilder.DropTable(name: "scan_campaigns");
        }
    }
}
