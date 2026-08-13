using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPhase8ScanExecutionFoundation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "security_targets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    BaseUrl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    TargetType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    MonitoringEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    ScanIntervalHours = table.Column<int>(type: "integer", nullable: false),
                    LastScanAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NextScanAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_targets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "security_provider_credentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    SecretReference = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    CredentialType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    LastValidatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ValidationStatus = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_provider_credentials", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "security_scan_tools",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ToolKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Version = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ImageReference = table.Column<string>(type: "text", nullable: false),
                    ImageDigest = table.Column<string>(type: "text", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Required = table.Column<bool>(type: "boolean", nullable: false),
                    CapabilitiesJson = table.Column<string>(type: "jsonb", nullable: false),
                    HealthStatus = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    LastHealthCheckUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_scan_tools", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "security_scan_jobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RepositoryId = table.Column<Guid>(type: "uuid", nullable: true),
                    TargetId = table.Column<Guid>(type: "uuid", nullable: true),
                    TargetUrl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    ScanProfile = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    RequestedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    CorrelationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CancelledAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    FailureReason = table.Column<string>(type: "text", nullable: true),
                    Version = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_scan_jobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_security_scan_jobs_repositories_RepositoryId",
                        column: x => x.RepositoryId,
                        principalTable: "repositories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_security_scan_jobs_security_targets_TargetId",
                        column: x => x.TargetId,
                        principalTable: "security_targets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_security_scan_jobs_users_RequestedByUserId",
                        column: x => x.RequestedByUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_security_provider_credentials_ProviderKey_SecretReference",
                table: "security_provider_credentials",
                columns: new[] { "ProviderKey", "SecretReference" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_CreatedAtUtc",
                table: "security_scan_jobs",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_RepositoryId",
                table: "security_scan_jobs",
                column: "RepositoryId");

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_RequestedByUserId",
                table: "security_scan_jobs",
                column: "RequestedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_Status",
                table: "security_scan_jobs",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_TargetId",
                table: "security_scan_jobs",
                column: "TargetId");

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_jobs_TargetUrl",
                table: "security_scan_jobs",
                column: "TargetUrl");

            migrationBuilder.CreateIndex(
                name: "IX_security_scan_tools_ToolKey",
                table: "security_scan_tools",
                column: "ToolKey",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "security_provider_credentials");

            migrationBuilder.DropTable(
                name: "security_scan_jobs");

            migrationBuilder.DropTable(
                name: "security_scan_tools");
        }
    }
}
