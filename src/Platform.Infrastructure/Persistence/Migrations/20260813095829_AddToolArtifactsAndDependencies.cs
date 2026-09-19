using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddToolArtifactsAndDependencies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ArtifactRepository",
                table: "security_scan_tools",
                type: "character varying(256)",
                maxLength: 256,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ArtifactSha256",
                table: "security_scan_tools",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ArtifactSignature",
                table: "security_scan_tools",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ArtifactSourceType",
                table: "security_scan_tools",
                type: "character varying(100)",
                maxLength: 100,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ContainerImageDigest",
                table: "security_scan_tools",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "tool_dependencies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ParentToolKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    DependencyToolKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    RequiredVersion = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    RequiredSha256 = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Required = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tool_dependencies", x => x.Id);
                });

            // The target table is owned by AddPhase8ScanExecutionFoundation. This migration
            // only adds the index that was introduced with the artifact/dependency model.
            migrationBuilder.CreateIndex(
                name: "IX_security_targets_BaseUrl",
                table: "security_targets",
                column: "BaseUrl");

            migrationBuilder.CreateIndex(
                name: "IX_tool_dependencies_ParentToolKey_DependencyToolKey",
                table: "tool_dependencies",
                columns: new[] { "ParentToolKey", "DependencyToolKey" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_security_targets_BaseUrl",
                table: "security_targets");

            migrationBuilder.DropTable(
                name: "tool_dependencies");

            migrationBuilder.DropColumn(
                name: "ArtifactRepository",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "ArtifactSha256",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "ArtifactSignature",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "ArtifactSourceType",
                table: "security_scan_tools");

            migrationBuilder.DropColumn(
                name: "ContainerImageDigest",
                table: "security_scan_tools");
        }
    }
}
