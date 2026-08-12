using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddApiHunterTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "api_hunter_records",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SourceRecordId = table.Column<long>(type: "bigint", nullable: false),
                    MaskedKey = table.Column<string>(type: "text", nullable: false),
                    RawKeyEncrypted = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    ApiType = table.Column<string>(type: "text", nullable: false),
                    SearchProvider = table.Column<string>(type: "text", nullable: false),
                    FirstFoundUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastFoundUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastCheckedUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ValidationResponse = table.Column<string>(type: "text", nullable: true),
                    Balance = table.Column<string>(type: "text", nullable: true),
                    AccountTier = table.Column<string>(type: "text", nullable: true),
                    AwsAccountId = table.Column<string>(type: "text", nullable: true),
                    AwsRiskLevel = table.Column<string>(type: "text", nullable: true),
                    ImportedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_api_hunter_records", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "api_hunter_sync_states",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    LastSyncedKeyId = table.Column<long>(type: "bigint", nullable: false),
                    LastSyncStartedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSyncCompletedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Status = table.Column<string>(type: "text", nullable: false),
                    RecordsImported = table.Column<int>(type: "integer", nullable: false),
                    RecordsUpdated = table.Column<int>(type: "integer", nullable: false),
                    RecordsSkipped = table.Column<int>(type: "integer", nullable: false),
                    ErrorMessage = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_api_hunter_sync_states", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "api_hunter_repo_references",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ApiHunterRecordId = table.Column<Guid>(type: "uuid", nullable: false),
                    SourceReferenceId = table.Column<long>(type: "bigint", nullable: false),
                    RepoUrl = table.Column<string>(type: "text", nullable: false),
                    RepoOwner = table.Column<string>(type: "text", nullable: false),
                    RepoName = table.Column<string>(type: "text", nullable: false),
                    FilePath = table.Column<string>(type: "text", nullable: false),
                    FileUrl = table.Column<string>(type: "text", nullable: false),
                    LineNumber = table.Column<int>(type: "integer", nullable: false),
                    CodeContext = table.Column<string>(type: "text", nullable: true),
                    FoundUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_api_hunter_repo_references", x => x.Id);
                    table.ForeignKey(
                        name: "FK_api_hunter_repo_references_api_hunter_records_ApiHunterReco~",
                        column: x => x.ApiHunterRecordId,
                        principalTable: "api_hunter_records",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_api_hunter_records_SourceRecordId",
                table: "api_hunter_records",
                column: "SourceRecordId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_api_hunter_records_Status_ApiType",
                table: "api_hunter_records",
                columns: new[] { "Status", "ApiType" });

            migrationBuilder.CreateIndex(
                name: "IX_api_hunter_repo_references_ApiHunterRecordId",
                table: "api_hunter_repo_references",
                column: "ApiHunterRecordId");

            migrationBuilder.CreateIndex(
                name: "IX_api_hunter_repo_references_RepoOwner_RepoName",
                table: "api_hunter_repo_references",
                columns: new[] { "RepoOwner", "RepoName" });

            migrationBuilder.CreateIndex(
                name: "IX_api_hunter_repo_references_SourceReferenceId",
                table: "api_hunter_repo_references",
                column: "SourceReferenceId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "api_hunter_repo_references");

            migrationBuilder.DropTable(
                name: "api_hunter_sync_states");

            migrationBuilder.DropTable(
                name: "api_hunter_records");
        }
    }
}
