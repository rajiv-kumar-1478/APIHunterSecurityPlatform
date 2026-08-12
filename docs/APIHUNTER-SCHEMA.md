# APIHunterV2 Schema & Mapping Specification

> **Discovered Schema Source of Truth**: Sourced directly from `APIHunterV2` repository models (`APIKey.cs`, `RepoReference.cs`, `SearchQuery.cs`, `CommonEnums.cs`) and `master_init.sql`.

---

## 1. Physical Tables Summary

### A. `APIKeys` Table

| Column Name | DB Type | Nullable | Description / Mapping |
|---|---|---|---|
| `Id` | `BIGINT` / `SERIAL` | No | Primary Key |
| `ApiKey` | `TEXT` | No | Unique raw API key candidate (Unique Index: `IX_APIKeys_ApiKey`) |
| `Status` | `INTEGER` | No | Enum (`-99`: Unverified, `0`: Invalid, `1`: Valid, `6`: Error, `7`: ValidNoCredits) |
| `ApiType` | `INTEGER` | No | Enum mapping to `ApiTypeEnum` (100=OpenAI, 120=Anthropic, 198=DeepSeek, 330=AWSIAM, etc.) |
| `SearchProvider` | `INTEGER` | No | Search provider integer (`1` = GitHub) |
| `LastCheckedUTC` | `TIMESTAMP WITH TZ` | Yes | Timestamp when validation was last performed |
| `FirstFoundUTC` | `TIMESTAMP WITH TZ` | No | Timestamp key was first scraped |
| `LastFoundUTC` | `TIMESTAMP WITH TZ` | No | Timestamp key was most recently encountered |
| `TimesDisplayed` | `INTEGER` | No | Access/view counter |
| `ErrorCount` | `INTEGER` | No | Verification failure counter |
| `ValidationResponse`| `TEXT` | Yes | Validation output / HTTP response snippet |
| `Balance` | `TEXT` | Yes | Account balance string (if applicable) |
| `AccountTier` | `TEXT` | Yes | Account tier string (e.g. `tier_1`, `pay_as_you_go`) |
| `DiscoveredByTelegramId` | `BIGINT` | Yes | Submitting telegram subscriber ID |
| `Metadata` | `TEXT` | Yes | JSON string with node info or extra metadata |
| `AwsAccountId` | `TEXT` | Yes | AWS-specific account ID |
| `AwsUserArn` | `TEXT` | Yes | AWS-specific IAM User ARN |
| `AwsUserId` | `TEXT` | Yes | AWS-specific IAM User ID |
| `AwsCredentialType` | `TEXT` | Yes | AWS credential type (`AccessKey`, `SessionToken`) |
| `AwsAttachedPolicies`| `TEXT` | Yes | JSON array of attached policies |
| `AwsRiskLevel` | `TEXT` | Yes | Assessed risk level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `AwsIsRootAccount` | `BOOLEAN` | No | True if root credentials |

---

### B. `RepoReferences` Table

| Column Name | DB Type | Nullable | Description / Mapping |
|---|---|---|---|
| `Id` | `BIGINT` / `SERIAL` | No | Primary Key |
| `APIKeyId` | `BIGINT` | No | Foreign Key → `APIKeys.Id` |
| `RepoURL` | `TEXT` | Yes | Canonical repository base URL (e.g., `https://github.com/owner/repo`) |
| `RepoOwner` | `TEXT` | Yes | Repository owner/organization name |
| `RepoName` | `TEXT` | Yes | Repository name |
| `RepoDescription` | `TEXT` | Yes | Repository description |
| `RepoId` | `BIGINT` | No | GitHub internal repo ID |
| `FileURL` | `TEXT` | Yes | Full file URL (with commit SHA) |
| `FileName` | `TEXT` | Yes | File name (e.g. `.env`, `config.json`) |
| `FilePath` | `TEXT` | Yes | Path within repository |
| `FileSHA` | `TEXT` | Yes | Git blob SHA |
| `ApiContentUrl` | `TEXT` | Yes | Raw content GitHub API URL |
| `CodeContext` | `TEXT` | Yes | Code context snippet surrounding discovered key |
| `LineNumber` | `INTEGER` | No | Line number in source file |
| `SearchQueryId` | `BIGINT` | No | Foreign Key → `SearchQueries.Id` |
| `FoundUTC` | `TIMESTAMP WITH TZ` | No | Timestamp reference was discovered |
| `Provider` | `TEXT` | Yes | Repository host provider (e.g. `GitHub`, `GitLab`) |
| `Branch` | `TEXT` | Yes | Repository branch (default `'main'`) |
| `RepoPushedAt` | `TIMESTAMP WITH TZ` | Yes | GitHub's `pushed_at` timestamp |

---

### C. `SearchQueries` Table

| Column Name | DB Type | Nullable | Description / Mapping |
|---|---|---|---|
| `Id` | `BIGINT` / `SERIAL` | No | Primary Key |
| `Query` | `TEXT` | No | Search query text |
| `IsEnabled` | `BOOLEAN` | No | Enabled status flag |
| `SearchResultsCount` | `INTEGER` | No | Cumulative search results count |
| `LastSearchUTC` | `TIMESTAMP WITH TZ` | No | Last search attempt timestamp |
| `LastDeepSearchDateUTC` | `TIMESTAMP WITH TZ` | Yes | Last deep search timestamp |
| `LastSuccessfulSearchUTC` | `TIMESTAMP WITH TZ` | Yes | Last search with ≥1 result |
| `LastRepoPushedSeenUTC` | `TIMESTAMP WITH TZ` | Yes | Checkpoint timestamp |

---

## 2. APIHunter Status Mapping Logic

The Platform domain maps APIHunter integer status codes via `IApiHunterStatusMapper`:

```
APIHunter ApiStatusEnum Value   ->   Platform Domain ApiKeyStatus
-----------------------------        ---------------------------
 1  (Valid)                   ->   PlatformStatus.Valid
 7  (ValidNoCredits)          ->   PlatformStatus.ValidNoCredits
 0  (Invalid)                 ->   PlatformStatus.Invalid
-99 (Unverified)              ->   PlatformStatus.Unverified
 6  (Error)                   ->   PlatformStatus.Error
 Any other integer            ->   PlatformStatus.Unknown
```

*Rule: Unknown status codes are NEVER silently coerced into Valid.*

---

## 3. Platform Data Normalization Model

To prevent duplicate entities on repeated synchronizations:
- **`ApiHunterSource`**: Identifies APIHunter DB connection.
- **`ApiHunterRecord`**: Tracks synced API keys by `(SourceId, ApiHunterKeyId)`. Raw key is masked by default in DTO queries.
- **`ApiHunterRepoReference`**: Tracks repository occurrences linked to imported records.
- **`Repository`**: Deduplicated canonical repository entities identified by `RepoURL` or `(RepoOwner, RepoName)`.
