# APIHunter Scanner Extension Developer Guide

## Overview

The APIHunter Platform uses a **capability-driven scanner architecture** where security scanning tools (such as `httpx`, `nuclei`, `subfinder`, `jsminer`, `bughunter`, and `semgrep`) are integrated as decoupled plugins via the locked `IScanToolAdapter` contract.

The core orchestration engine, campaign scheduler, and Phase 8 finding ingestion pipeline are **100% scanner-agnostic**. The platform plans scans dynamically by matching target asset kinds, security profiles, and requested capabilities without hardcoded tool invocations.

---

## Guide Index

| Document | Description |
|---|---|
| [`adapter-contract.md`](./adapter-contract.md) | Universal `IScanToolAdapter` interface, lifecycle, and execution contracts. |
| [`manifest-and-provenance.md`](./manifest-and-provenance.md) | `ScanToolManifest` rules, OCI registry digests, and provenance validation. |
| [`capability-taxonomy.md`](./capability-taxonomy.md) | Platform capability taxonomy tags, target asset types, and execution phases. |
| [`output-parser-contract.md`](./output-parser-contract.md) | Bounded streaming parser requirements, resource limits, and error resilience. |
| [`sandbox-requirements.md`](./sandbox-requirements.md) | `IScannerRuntimeSandbox` execution, capability dropping, and network isolation. |
| [`finding-mapping.md`](./finding-mapping.md) | Mapping tool findings to `FindingCandidate`, evidence redaction, and canonical v1 fingerprinting. |
| [`testing-requirements.md`](./testing-requirements.md) | Golden fixtures, adversarial parsing, manifest validation, and plan determinism tests. |
| [`adding-a-new-scanner.md`](./adding-a-new-scanner.md) | Step-by-step developer checklist for onboarding a new scanner plugin. |

---

## Architectural Authority Flow

```text
               Target & Scope Specification
          (WebEndpoint / Repo / Contract / JS)
                          │
                          ▼
                  ScanPlanningEngine
           (Capability Matching & Policies)
                          │
                          ▼
                  ResolvedScanPlan
              (Audit PlanHash Generated)
                          │
                          ▼
               IScannerRuntimeSandbox
            (OCI Container / Drop-All Caps)
                          │
                          ▼
                 Streaming Output Parser
            (Resource Limits & Malformed Guard)
                          │
                          ▼
                  FindingCandidate
                          │
                          ▼
                  EvidenceSanitizer
             (Multi-Layer Redaction Filter)
                          │
                          ▼
              FindingFingerprintService
              (Canonical v1 SHA-256 Digest)
                          │
                          ▼
               Phase 8 Findings Ingestion
```
