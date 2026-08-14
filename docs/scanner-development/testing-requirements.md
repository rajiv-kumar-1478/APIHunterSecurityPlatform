# Scanner Plugin Testing Requirements

## Test Verification Standards

Every scanner adapter submitted to APIHunter must include a comprehensive unit test fixture covering:

---

## Required Test Matrix

### 1. Manifest Supply Chain Validation
- Verify `ScanToolManifestValidator.Validate(adapter.Manifest).IsValid == true`.
- Assert exact SemVer, valid container image repository, and valid 64-char hex SHA-256 digest (`sha256:...`).
- Assert supported profile flags (`Standard`, `Deep`).

### 2. CLI Execution Plan Generation
- Verify command line arguments produced by `adapter.PrepareExecution(context)`.
- Assert profile-specific arguments (e.g. standard rule packs vs. deep framework rules).
- Assert environment variables (e.g. metrics disabled).

### 3. Golden JSON Fixture Parsing
- Parse authentic tool output fixture.
- Verify accurate mapping of `FindingCandidate` properties: `RawSeverity`, `CweId`, `EndpointPath`, `RuleOrTemplateId`, and evidence snippets.
- Verify `ScannerCoverage` calculations.

### 4. Adversarial & Resource Limit Guard Tests
- **Excessive Payload**: Feed `MaxRawOutputBytes + 1` bytes $\rightarrow$ verify safe truncation without OOM.
- **Excessive Candidates**: Feed 2,000 items $\rightarrow$ verify candidate capping at `MaxCandidates = 1,000`.
- **Corrupt Lines**: Feed malformed lines interleaved with valid JSON $\rightarrow$ verify parser skips corrupt lines and records `MalformedRecordCount`.

### 5. PlanHash & Capability Resolution Tests
- Verify that `ScanPlanningEngine.PlanScan()` correctly includes the new adapter when matching required capabilities and target kinds.
- Verify deterministic `PlanHash` across identical inputs.
