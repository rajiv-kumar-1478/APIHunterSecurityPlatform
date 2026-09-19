# APIHunter Scanner Extension Developer Guide

## Overview

APIHunter uses capability-driven planning, canonical parser output, and platform-owned finding/provenance models. Tools with verified adapters include code-level implementations such as HTTP probing, static analysis, and secret scanning components; BugHunter is planned but currently unavailable.

The orchestration and ingestion layers do not consume scanner-specific output. That does not mean every scanner is configuration-only: a tool with a new CLI/output contract needs an adapter, parser, DI registration, planning policy, and tests. Configuration-only onboarding applies only to a tool already conforming to the approved generic CLI/parser/runtime contract.

## Current availability boundary

The checked-in production/Compose runtime is disabled and fail-closed. A valid manifest, parser, or unit test does not make a scanner operational. Runtime enablement additionally requires immutable artifact provenance, a physical sandbox/egress boundary, and successful live Docker validation.

## Guide index

| Document | Description |
|---|---|
| [`adapter-contract.md`](./adapter-contract.md) | Typed and generic adapter responsibilities. |
| [`manifest-and-provenance.md`](./manifest-and-provenance.md) | Immutable manifest and provenance rules. |
| [`capability-taxonomy.md`](./capability-taxonomy.md) | Capability tags, target kinds, and phases. |
| [`output-parser-contract.md`](./output-parser-contract.md) | Bounded parser and malformed-output requirements. |
| [`sandbox-requirements.md`](./sandbox-requirements.md) | Normative isolation and live-validation gate. |
| [`finding-mapping.md`](./finding-mapping.md) | Canonical findings, redaction, and active-verification authority. |
| [`testing-requirements.md`](./testing-requirements.md) | Unit, integration, live-container, and PostgreSQL evidence tiers. |
| [`dashboard-integration.md`](./dashboard-integration.md) | Canonical UI models and truthful availability states. |
| [`adding-a-new-scanner.md`](./adding-a-new-scanner.md) | End-to-end onboarding checklist. |

## Authority flow

```text
registered tenant target + requested profile
        ▼
capability planner and immutable manifest
        ▼
IScannerRuntimeSandbox (must be operational)
        ▼
typed/generic adapter + bounded parser
        ▼
FindingCandidate + ScannerCoverage
        ▼
evidence sanitization and canonical ingestion
        ▼
platform DTOs, reports, provenance, and audit
```

If the runtime, provenance, target scope, credentials, or egress boundary is unavailable, stop before execution and report a stable fail-closed status.
