using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Adds tenant_provider_settings table to support customer-configurable provider endpoints,
    /// specifically Azure OpenAI resource endpoints (e.g. https://{resource}.openai.azure.com).
    ///
    /// Keyed by (TenantId, ProviderName) to enforce unique per-tenant provider configuration.
    /// Down is intentionally irreversible (SQLSTATE 0A000).
    /// </summary>
    [DbContext(typeof(PlatformDbContext))]
    [Migration("20260920000002_AddTenantProviderSettingsTable")]
    public partial class AddTenantProviderSettingsTable : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "tenant_provider_settings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ResourceEndpointUrl = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    ApiVersion = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false, defaultValue: "2023-05-15"),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tenant_provider_settings", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_tenant_provider_settings_TenantId_ProviderName",
                table: "tenant_provider_settings",
                columns: new[] { "TenantId", "ProviderName" },
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DO $$ BEGIN
                    RAISE EXCEPTION 'Down migration for AddTenantProviderSettingsTable is intentionally blocked. '
                        'Drain and archive tenant provider settings before dropping table.'
                        USING ERRCODE = '0A000';
                END $$;
                """);
        }
    }
}
