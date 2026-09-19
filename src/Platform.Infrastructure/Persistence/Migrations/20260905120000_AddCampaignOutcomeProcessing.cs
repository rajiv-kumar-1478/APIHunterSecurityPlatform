using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations;

/// <summary>
/// Adds a durable per-job campaign outcome marker. Existing terminal campaign jobs
/// are backfilled as already processed so deployment cannot replay historical outcomes.
/// </summary>
[DbContext(typeof(PlatformDbContext))]
[Migration("20260905120000_AddCampaignOutcomeProcessing")]
public partial class AddCampaignOutcomeProcessing : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<DateTime>(
            name: "CampaignOutcomeProcessedAtUtc",
            table: "security_scan_jobs",
            type: "timestamp with time zone",
            nullable: true);

        migrationBuilder.Sql(
            """
            UPDATE security_scan_jobs
            SET "CampaignOutcomeProcessedAtUtc" = COALESCE("CompletedAtUtc", NOW())
            WHERE "CampaignId" IS NOT NULL
              AND "Status" IN (
                  'Completed',
                  'CompletedWithWarnings',
                  'Partial',
                  'Failed',
                  'Cancelled',
                  'TimedOut',
                  'Blocked')
              AND "CampaignOutcomeProcessedAtUtc" IS NULL;
            """);

        migrationBuilder.CreateIndex(
            name: "IX_security_scan_jobs_CampaignId_CampaignOutcomeProcessedAtUtc",
            table: "security_scan_jobs",
            columns: new[] { "CampaignId", "CampaignOutcomeProcessedAtUtc" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "IX_security_scan_jobs_CampaignId_CampaignOutcomeProcessedAtUtc",
            table: "security_scan_jobs");

        migrationBuilder.DropColumn(
            name: "CampaignOutcomeProcessedAtUtc",
            table: "security_scan_jobs");
    }
}
