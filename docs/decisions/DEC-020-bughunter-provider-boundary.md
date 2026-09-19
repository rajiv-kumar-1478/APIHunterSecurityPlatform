# DEC-020: BugHunter Scan Provider Boundary & Replacement Architecture

- **Status**: Accepted boundary; operational availability superseded/clarified by DEC-022
- **Original date**: 2026-08-13
- **Clarified**: 2026-09-05
- **Context**: The platform needs a stable compatibility boundary for a possible BugHunter integration without allowing unverified CLI/API/package behavior into domain or application logic. No authoritative BugHunter image/API/CLI, authentication, output, cancellation, artifact, or isolation contract is currently available.
- **Decision**:
  1. **Provider boundary**: BugHunter remains behind `IBugHunterProvider` / `IScanProvider`; core code never invokes BugHunter-specific commands.
  2. **Unavailable by default**: `BugHunterScanProvider` returns `BUGHUNTER_CONTRACT_UNAVAILABLE`/blocked for start, status, result, and cancellation. It must not fabricate state or fall back to host execution.
  3. **Capability intent is not availability**: Capability mapping may describe a future provider, but planning/health cannot treat BugHunter as operational until authoritative contracts and live probes exist.
  4. **Secret isolation**: Any future implementation must lease only required secrets in memory and keep them out of DTOs, logs, command lines, artifacts, and persistence.
  5. **Reversible implementation**: A future provider may be implemented behind this boundary without changing canonical findings or graph models, but adapter/parser/DI/policy and contract tests are expected where required.
- **Impact**: The architecture can accept a future verified implementation while current APIs and UI remain truthful and fail closed.
