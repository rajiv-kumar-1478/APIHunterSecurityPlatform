# Scanning Tool Capability Intent

This document is a capability-intent inventory. It is **not** an operational health manifest. The current production/Compose scanner runtime is disabled and fail-closed.

> Never publish `Healthy`, `Required`, a version, or a digest until the exact artifact and runtime probe have been verified. Placeholder `pinned-v...` values are prohibited.

| Tool Key | Intended capability | Version/digest authority | Current availability |
|---|---|---|---|
| `subfinder` | Subdomain discovery | Not established in checked-in deployment | Disabled / not configured |
| `httpx` | HTTP probing and DNS resolution | Not established in checked-in deployment | Disabled / not configured |
| `katana` | URL crawling | Not established in checked-in deployment | Disabled / not configured |
| `nuclei` | Template vulnerability scanning | Not established in checked-in deployment | Disabled / not configured |
| `bughunter` | Planned hosted-provider compatibility | No authoritative provider/image/CLI contract | **Unavailable — `BUGHUNTER_CONTRACT_UNAVAILABLE`** |

## Availability rules

1. Registry capability metadata describes what a verified tool could provide; it does not prove execution availability.
2. Tool health is runtime evidence and must not be inferred from registration, mocks, parser fixtures, or unit tests.
3. Operational status requires immutable provenance, a successful capability probe, compatible parser output, configured sandbox, and enforced egress.
4. If any required boundary is absent, the runtime reports unavailable/fail-closed and scan admission remains disabled.
