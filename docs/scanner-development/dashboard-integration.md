# Dashboard Integration & Canonical UI Read Models

## UI decoupling invariant

The dashboard consumes platform-owned canonical DTOs only. Scanner JSON/XML/CLI output never crosses the adapter/parser boundary. Adding a conforming tool must not require a scanner-specific UI component.

## Boundary matrix

| Layer | Scanner-specific format? | Role |
|---|---:|---|
| Scanner binary | Yes | Emits raw output inside the sandbox. |
| Adapter/parser | Yes | Translation and resource-boundary layer. |
| Finding/coverage/provenance DTOs | No | Canonical platform contracts. |
| Database and audit | No | Authoritative normalized persistence. |
| Dashboard | No | Renders canonical data and truthful availability. |

## Canonical views

- **Findings**: normalized severity/classification/location, sanitized evidence, lifecycle, and history.
- **Provenance**: plan hash, planner/registry versions, verified artifact digest, rule sets, and invocation timeline.
- **AI advisory**: explicitly advisory explanation/remediation with model/prompt provenance; never finding authority.
- **Tool/runtime health**: capabilities, profile support, verified provenance, diagnostics, and operational status.

## Required status semantics

The UI must support at least:
- `Healthy`: authoritative runtime probe succeeded and required boundaries are ready.
- `Degraded`: operational but impaired, with diagnostics.
- `DisabledByPolicy` or `Disabled`: intentionally disabled.
- `NotConfigured`: required executor, image, credentials, or gateway configuration is absent.
- `Unavailable`: provider/runtime contract cannot execute (for example `BUGHUNTER_CONTRACT_UNAVAILABLE`).
- `FailClosed`: a security boundary rejected execution (for example `SCANNER_RUNTIME_DISABLED`).

Never render registry presence, mock success, parser availability, or a placeholder version as `Healthy`. The default/Compose scanner runtime is disabled and BugHunter is unavailable.
