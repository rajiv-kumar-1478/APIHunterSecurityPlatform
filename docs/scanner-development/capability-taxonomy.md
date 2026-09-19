# Scanner Capability Taxonomy & Execution Phases

Capability entries describe planning intent. A listed example is not proof that the tool is installed, healthy, or operational. BugHunter and ZAP examples below are planned/unavailable unless an authoritative runtime contract is later enabled.

## Execution phases (`ScannerExecutionPhase`)

```text
Discovery → StaticAnalysis → AttackSurfaceAnalysis → ActiveVerification
```

| Phase | Typical implemented/planned examples | Responsibility |
|---|---|---|
| `Discovery` | `httpx`, `subfinder`, `jsminer` | HTTP/DNS probing, crawling, and asset discovery. |
| `StaticAnalysis` | `semgrep`, `trufflehog` | SAST, history, secret, and configuration analysis. |
| `AttackSurfaceAnalysis` | `UnifiedJsAnalyzer` | AST/routes/client-side attack-surface analysis. |
| `ActiveVerification` | `nuclei`; planned `bughunter`, `zap` | Controlled active verification against an authorized target. |

## Canonical capability tags

| Capability | Example provider intent |
|---|---|
| `http.probe` | `httpx` |
| `subdomain.enumerate` | `subfinder` |
| `js.crawl` | `jsminer` |
| `endpoint.extract` | `jsminer`, `UnifiedJsAnalyzer` |
| `sast.scan`, `code.vulnerability` | `semgrep` |
| `secret.detect` | `jsminer`, `JsSecretAnalyzer` |
| `secret.deep_scan` | `trufflehog` |
| `template.vulnerability` | `nuclei` |
| `api.fuzz`, `bola.verify` | planned BugHunter compatibility |
| `dast.active_fuzz` | planned ZAP compatibility |

## Target asset kinds

- `WebEndpoint`: one web/API endpoint.
- `Domain`: domain or authorized subdomain scope.
- `SourceRepository`: source repository/artifact.
- `JavaScriptBundle`: JavaScript asset.
- `ApiContract`: OpenAPI/GraphQL contract.

Planning must select only enabled, healthy, provenance-valid tools supported by an operational runtime. Otherwise it fails closed.
