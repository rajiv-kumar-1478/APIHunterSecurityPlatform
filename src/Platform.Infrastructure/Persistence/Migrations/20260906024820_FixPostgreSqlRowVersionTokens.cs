using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Platform.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class FixPostgreSqlRowVersionTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // New binaries use PostgreSQL's native xmin system column. After every pre-tenant
            // scan-job binary has drained, keep the legacy bytea columns generated so the
            // immediately preceding tenant-aware model remains safe during the token cutover.
            migrationBuilder.Sql(
                """
                ALTER TABLE "repositories"
                    ADD COLUMN IF NOT EXISTS "RowVersion" bytea;

                ALTER TABLE "repositories"
                    ALTER COLUMN "RowVersion"
                    SET DEFAULT convert_to(txid_current()::text, 'UTF8');

                DO $repositories_backfill$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = 'repositories'::regclass
                          AND attribute.attname = 'RowVersion'
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                          AND NOT attribute.attnotnull
                    ) THEN
                        UPDATE "repositories"
                        SET "RowVersion" = convert_to(txid_current()::text, 'UTF8')
                        WHERE "RowVersion" IS NULL;

                        ALTER TABLE "repositories"
                            ALTER COLUMN "RowVersion" SET NOT NULL;
                    END IF;
                END
                $repositories_backfill$;

                CREATE OR REPLACE FUNCTION "apihunter_set_repositories_legacy_row_version"()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $repositories_row_version$
                BEGIN
                    NEW."RowVersion" := convert_to(txid_current()::text, 'UTF8');
                    RETURN NEW;
                END;
                $repositories_row_version$;

                DROP TRIGGER IF EXISTS "TR_repositories_legacy_RowVersion"
                    ON "repositories";

                CREATE TRIGGER "TR_repositories_legacy_RowVersion"
                    BEFORE UPDATE ON "repositories"
                    FOR EACH ROW
                    EXECUTE FUNCTION "apihunter_set_repositories_legacy_row_version"();

                ALTER TABLE "analysis_jobs"
                    ADD COLUMN IF NOT EXISTS "RowVersion" bytea;

                ALTER TABLE "analysis_jobs"
                    ALTER COLUMN "RowVersion"
                    SET DEFAULT convert_to(txid_current()::text, 'UTF8');

                DO $analysis_jobs_backfill$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_attribute AS attribute
                        WHERE attribute.attrelid = 'analysis_jobs'::regclass
                          AND attribute.attname = 'RowVersion'
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                          AND NOT attribute.attnotnull
                    ) THEN
                        UPDATE "analysis_jobs"
                        SET "RowVersion" = convert_to(txid_current()::text, 'UTF8')
                        WHERE "RowVersion" IS NULL;

                        ALTER TABLE "analysis_jobs"
                            ALTER COLUMN "RowVersion" SET NOT NULL;
                    END IF;
                END
                $analysis_jobs_backfill$;

                CREATE OR REPLACE FUNCTION "apihunter_set_analysis_jobs_legacy_row_version"()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $analysis_jobs_row_version$
                BEGIN
                    NEW."RowVersion" := convert_to(txid_current()::text, 'UTF8');
                    RETURN NEW;
                END;
                $analysis_jobs_row_version$;

                DROP TRIGGER IF EXISTS "TR_analysis_jobs_legacy_RowVersion"
                    ON "analysis_jobs";

                CREATE TRIGGER "TR_analysis_jobs_legacy_RowVersion"
                    BEFORE UPDATE ON "analysis_jobs"
                    FOR EACH ROW
                    EXECUTE FUNCTION "apihunter_set_analysis_jobs_legacy_row_version"();

                -- The original hand-written CREATE INDEX used an unquoted identifier, so
                -- PostgreSQL folded the physical name to lowercase while the EF model and
                -- exception classifier use the quoted canonical name.
                ALTER INDEX IF EXISTS ix_security_scan_jobs_campaign_occurrence_key
                    RENAME TO "IX_security_scan_jobs_campaign_occurrence_key";

                -- Phase 8 used Version as the scan-job optimistic concurrency token. Phase 9
                -- introduced JobVersion as its replacement but did not migrate or remove Version.
                -- Keep the physical counters synchronized for tenant-schema-compatible clients;
                -- this does not make pre-tenant application binaries schema-compatible.
                ALTER TABLE "security_scan_jobs"
                    ADD COLUMN IF NOT EXISTS "Version" integer NOT NULL DEFAULT 1;

                ALTER TABLE "security_scan_jobs"
                    ALTER COLUMN "Version" SET DEFAULT 1;

                UPDATE "security_scan_jobs"
                SET "Version" = GREATEST("Version", "JobVersion"),
                    "JobVersion" = GREATEST("Version", "JobVersion")
                WHERE "Version" IS DISTINCT FROM "JobVersion";

                CREATE OR REPLACE FUNCTION "apihunter_sync_security_scan_job_versions"()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $security_scan_job_versions$
                BEGIN
                    IF TG_OP = 'INSERT' THEN
                        NEW."Version" := GREATEST(
                            COALESCE(NEW."Version", 1),
                            COALESCE(NEW."JobVersion", 1));
                        NEW."JobVersion" := NEW."Version";
                    ELSIF NEW."Version" IS DISTINCT FROM OLD."Version"
                       AND NEW."JobVersion" IS NOT DISTINCT FROM OLD."JobVersion" THEN
                        NEW."JobVersion" := NEW."Version";
                    ELSIF NEW."JobVersion" IS DISTINCT FROM OLD."JobVersion"
                       AND NEW."Version" IS NOT DISTINCT FROM OLD."Version" THEN
                        NEW."Version" := NEW."JobVersion";
                    ELSIF NEW."Version" IS DISTINCT FROM OLD."Version"
                       AND NEW."JobVersion" IS DISTINCT FROM OLD."JobVersion"
                       AND NEW."Version" IS DISTINCT FROM NEW."JobVersion" THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '23000',
                            MESSAGE = 'security_scan_jobs Version and JobVersion cannot advance to different values';
                    END IF;

                    RETURN NEW;
                END;
                $security_scan_job_versions$;

                DROP TRIGGER IF EXISTS "TR_security_scan_jobs_version_bridge"
                    ON "security_scan_jobs";

                CREATE TRIGGER "TR_security_scan_jobs_version_bridge"
                    BEFORE INSERT OR UPDATE OF "Version", "JobVersion"
                    ON "security_scan_jobs"
                    FOR EACH ROW
                    EXECUTE FUNCTION "apihunter_sync_security_scan_job_versions"();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DO $irreversible$
                BEGIN
                    RAISE EXCEPTION USING
                        ERRCODE = '0A000',
                        MESSAGE = 'Migration 20260906024820_FixPostgreSqlRowVersionTokens is intentionally irreversible: legacy bytea RowVersion generation and the security_scan_jobs Version/JobVersion synchronization are expand/contract compatibility bridges. Do not migrate down automatically; tenant-schema-compatible legacy-token binaries can use this bridge schema, but pre-tenant scan-job binaries cannot. Removal requires a separately reviewed contract migration after the tenant-aware legacy-token instances and rollback window have drained.';
                END
                $irreversible$;
                """);
        }
    }
}
