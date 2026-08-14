# Step-by-Step Guide: Adding a New Scanner to APIHunter

Follow this checklist to onboard a new scanner (e.g. **TruffleHog**, **OWASP ZAP**, **ffuf**, **Trivy**, or custom security tools):

---

## 15-Step Developer Checklist

1. **Identify Capability Tags**:
   - Determine the capabilities provided (e.g. `secret.deep_scan`, `git.history`, `dast.active_fuzz`).
   - Add new capability tags to [`capability-taxonomy.md`](./capability-taxonomy.md) if introducing new categories.

2. **Determine Target Asset Kind**:
   - Classify targets: `WebEndpoint`, `Domain`, `SourceRepository`, `JavaScriptBundle`, or `ApiContract`.

3. **Obtain Authentic Container Image & Digest**:
   - Find the official OCI image from Docker Hub or GitHub Container Registry.
   - Run `docker pull <image>:<tag>` or query the registry API to get the exact multi-arch SHA-256 digest (`sha256:...`).

4. **Define `ScanToolManifest`**:
   - Set `ToolKey`, `Version`, `ContainerImageDigest`, `SupportedProfiles`, `Capabilities`, `DiscoveredAssetTypes`, and `ExecutionPhase`.

5. **Implement `XxxOutputParser.cs`**:
   - Create parser in `src/Platform.Application/Scanning/Parsers/`.
   - Implement streaming JSON/JSONL reader.
   - Enforce `MaxRawOutputBytes` (10 MiB), `MaxCandidates` (1,000), and `MaxEvidenceBytes` (16 KiB).
   - Return `ToolParsedOutputResult` with `ScannerCoverage`.

6. **Implement `XxxAdapter.cs`**:
   - Create adapter in `src/Platform.Application/Scanning/Adapters/` implementing `IScanToolAdapter`.
   - Formulate sandbox CLI execution arguments in `PrepareExecution`.
   - Delegate output parsing to `_parser.ParseAsync()`.

7. **Add Deterministic Rule/Execution Policies (Optional)**:
   - If the tool uses external rule packs (like Semgrep, Nuclei, or ZAP), define an immutable policy record (e.g. `XxxRulePolicy`) with versioned rule sets.

8. **Register in Dependency Injection**:
   - Register parser and adapter in `src/Platform.Api/Program.cs` and `src/Platform.Worker/Program.cs`:
     ```csharp
     builder.Services.AddSingleton<XxxOutputParser>();
     builder.Services.AddSingleton<IScanToolAdapter, XxxAdapter>();
     ```

9. **Configure Selection Policy in `ScanPlanningEngine`**:
   - Add default preference mapping in `ScanPlanningEngine.BuildPolicyLookup()` if the tool serves as a primary provider for its capabilities.

10. **Create Golden JSON Test Fixtures**:
    - Add real sample scanner output to `tests/Platform.UnitTests/Scanning/Adapters/XxxAdapterTests.cs`.

11. **Write Comprehensive Unit Tests**:
    - Validate Manifest, CLI arguments generation, golden parsing, and adversarial resource limit protections.

12. **Write Capability Planning Unit Tests**:
    - Add a test in `ScanPlanningEngineTests.cs` asserting that `PlanScan()` selects your new adapter for its target asset kind and capabilities.

13. **Run Full Test Suite**:
    - `dotnet test tests/Platform.UnitTests/`
    - `dotnet test tests/Platform.IntegrationTests/`

14. **Verify PlanHash Determinism**:
    - Ensure `PlanHash` remains deterministic and reproducible across identical target inputs.

15. **Document the New Adapter**:
    - Update `docs/SPEC-008_SCANNER_CAPABILITY_EXPANSION_CONTRACT.md` with the new tool's capability profile and container digest.
