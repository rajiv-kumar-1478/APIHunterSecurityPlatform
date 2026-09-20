# APIHunter Security Platform — Disaster Recovery (DR) & Point-in-Time Recovery Runbook

**Document Version:** 1.0.0  
**Phase Reference:** Phase 11 — Production Hardening  
**Target Audience:** SREs, Security Operations, and Platform Administrators

---

## 1. Overview & Recovery Objectives
- **RTO (Recovery Time Objective):** $< 30$ minutes to restore full platform scanning and API operations.
- **RPO (Recovery Point Objective):** $< 5$ minutes of data loss utilizing continuous Write-Ahead Log (WAL) archiving.

---

## 2. Cryptographic Key Ring Recovery
The platform utilizes **ASP.NET Core Data Protection** and master encryption keys (`Security:MasterEncryptionKey` / `DataProtection:MasterKey`) for credential storage and CI/CD webhook secrets.

> [!CAUTION]
> If the Data Protection key ring or Master Encryption Key is lost, existing encrypted credentials and HMAC secrets **cannot** be decrypted. Both the database dump and the key ring must be backed up together.

### 2.1 Restoring the Data Protection Key Ring
1. Ensure the key ring directory `/var/secrets/dataprotection` (or registry/blob store) is restored prior to starting the web application or workers:
   ```bash
   tar -xzf dataprotection_keys_backup.tar.gz -C /var/secrets/dataprotection
   chmod 700 /var/secrets/dataprotection
   chmod 600 /var/secrets/dataprotection/*.xml
   ```
2. Verify environment variable `DATA_PROTECTION_KEY_DIR=/var/secrets/dataprotection`.

---

## 3. Database Restoration Procedure (PostgreSQL)

### 3.1 Full Database Restore from Dump
1. Validate SHA-256 integrity of the backup artifact:
   ```bash
   sha256sum -c apihunter_platform_full_20260920_120000Z.dump.gz.sha256
   ```
2. Stop active API and Worker services to prevent concurrent schema contention:
   ```bash
   systemctl stop apihunter-api apihunter-worker
   ```
3. Drop and recreate clean database target:
   ```bash
   dropdb -h localhost -U postgres --if-exists apihunter_platform
   createdb -h localhost -U postgres -O apihunter apihunter_platform
   ```
4. Restore from compressed archive using `pg_restore`:
   ```bash
   gunzip -c apihunter_platform_full_20260920_120000Z.dump.gz | pg_restore -h localhost -U postgres -d apihunter_platform -v
   ```

---

## 4. Verification & Post-Restore Health Checks

Execute the following post-recovery checks:
1. **Database Schema Verification:**
   Ensure all EF Core migrations are recorded in `__EFMigrationsHistory`:
   ```sql
   SELECT "MigrationId", "ProductVersion" FROM "__EFMigrationsHistory" ORDER BY "MigrationId" DESC LIMIT 5;
   ```
2. **Tenant & Identity Parity:**
   Confirm tenant identity records and admin accounts exist:
   ```sql
   SELECT "Id", "Email", "IsPlatformAdmin" FROM users WHERE "IsPlatformAdmin" = true;
   ```
3. **Queue Health & Orphan Cleanup:**
   Reset any jobs that were stuck in `Running` during the crash to `Pending`:
   ```sql
   UPDATE security_scan_jobs
   SET status = 0, worker_id = NULL
   WHERE status = 1;
   ```
4. **Service Health Probes:**
   Start services and query readiness:
   ```bash
   curl -f http://localhost:5000/health/ready
   # Expected response: {"status":"Ready","database":"Connected",...}
   ```
5. **Trigger Autonomous Cycle:**
   Invoke `/api/v1/operations/cycle` to verify that the Incident Engine resumes continuous monitoring.
