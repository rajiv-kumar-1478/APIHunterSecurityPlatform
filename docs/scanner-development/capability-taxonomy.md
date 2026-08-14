# Scanner Capability Taxonomy & Execution Phases

## Execution Phases (`ScannerExecutionPhase`)

The planner arranges tool invocations into strictly ordered phases:

```text
Discovery (1) ──────► StaticAnalysis (2) ──────► AttackSurfaceAnalysis (3) ──────► ActiveVerification (4)
```

| Phase | Value | Typical Tools | Responsibilities |
|---|---|---|---|
| **`Discovery`** | `1` | `httpx`, `subfinder`, `jsminer` | Network probing, DNS resolution, JavaScript crawling, URL discovery. |
| **`StaticAnalysis`** | `2` | `semgrep`, `trufflehog` | Code-level SAST, git history scanning, config auditing. |
| **`AttackSurfaceAnalysis`** | `3` | `UnifiedJsAnalyzer` | AST parsing, client-side route extraction, secret deduplication, DOM-XSS. |
| **`ActiveVerification`** | `4` | `nuclei`, `bughunter`, `zap` | Active HTTP probing, BOLA verification, payload injection verification. |

---

## Canonical Capability Tags

| Capability Tag | Category | Satisfying Tools (Examples) |
|---|---|---|
| `http.probe` | Network Discovery | `httpx` |
| `subdomain.enumerate` | Reconnaissance | `subfinder` |
| `js.crawl` | Asset Discovery | `jsminer` |
| `endpoint.extract` | Surface Discovery | `jsminer`, `UnifiedJsAnalyzer` |
| `sast.scan` | Static Analysis | `semgrep` |
| `code.vulnerability` | Static Analysis | `semgrep` |
| `secret.detect` | Secret Intelligence | `jsminer`, `JsSecretAnalyzer` |
| `secret.deep_scan` | Secret Intelligence | `trufflehog` |
| `template.vulnerability` | Active Vulnerability | `nuclei` |
| `api.fuzz` | Active Verification | `bughunter` |
| `bola.verify` | Active Verification | `bughunter` |
| `dast.active_fuzz` | Active Verification | `zap` |

---

## Target Asset Kinds (`TargetAssetKind`)

1. **`WebEndpoint`**: Single URL or web application service.
2. **`Domain`**: Top-level domain or wildcard host.
3. **`SourceRepository`**: Git repository or local source directory.
4. **`JavaScriptBundle`**: Static or bundled JavaScript artifact.
5. **`ApiContract`**: OpenAPI/Swagger or GraphQL schema specification.
