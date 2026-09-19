using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Step 9.4 — Deployment Webhook Wiring
    ///
    /// Creates two tables:
    ///   registered_applications  — per-application HMAC secret + authorized target URL,
    ///                              keyed by (TenantId, ApplicationId).
    ///   deployment_webhook_records — durable idempotency log, written AFTER scan-job
    ///                                creation so that failed enqueues remain retryable.
    ///
    /// Down is intentionally irreversible (SQLSTATE 0A000) — removing these tables while
    /// webhook integrations are active would silently break CI/CD verification.
    /// </summary>
    public partial class AddDeploymentWebhookTables : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "registered_applications",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ApplicationId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    AuthorizedTargetUrl = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    Environment = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    EncryptedWebhookSecret = table.Column<string>(type: "text", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_registered_applications", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_registered_applications_TenantId_ApplicationId",
                table: "registered_applications",
                columns: new[] { "TenantId", "ApplicationId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_registered_applications_Enabled",
                table: "registered_applications",
                column: "Enabled");

            migrationBuilder.CreateTable(
                name: "deployment_webhook_records",
                columns: table => new
                {
                    WebhookId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ApplicationId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ScanJobId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProcessedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_deployment_webhook_records", x => x.WebhookId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_deployment_webhook_records_ProcessedAtUtc",
                table: "deployment_webhook_records",
                column: "ProcessedAtUtc");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Deliberately irreversible — removing these tables while active webhook integrations
            // exist would silently drop idempotency guarantees and authorization records.
            migrationBuilder.Sql(
                """
                DO $$ BEGIN
                    RAISE EXCEPTION 'Down migration for AddDeploymentWebhookTables is intentionally blocked. '
                        'Drain all webhook integrations before removing registered_applications or deployment_webhook_records.'
                        USING ERRCODE = '0A000';
                END $$;
                """);
        }
    }
}
