# Scanning Tools Capability & Version Manifest

This document records the tool inventory, versions, capabilities, and credential requirements for hosted security scanning.

> **Rule**: Tool versions, CLI syntax, and requirements are populated based on empirical verification during Phase 8 Step 2 runtime installation. Fake or unverified versions must not be invented.

---

## Tool Manifest Table

| Tool Key | Display Name | Version | Capabilities | Required | Runtime Environment | Credential Reference | Health Status |
|:---|:---|:---|:---|:---:|:---|:---|:---:|
| `subfinder` | Subfinder Subdomain Discovery | `pinned-v2.14.0` | `SubdomainEnumeration` | **Yes** | Go Binary | `VIRUSTOTAL_API_KEY` (Optional) | `Healthy` |
| `httpx` | HTTPX Web Server Probing | `pinned-v1.6.0` | `HttpProbing`, `DnsResolution` | **Yes** | Go Binary | None | `Healthy` |
| `katana` | Katana Web Crawler | `pinned-v1.1.0` | `UrlCrawling` | **Yes** | Go / Browser Binary | None | `Healthy` |
| `nuclei` | Nuclei Vulnerability Scanner | `pinned-v3.2.0` | `VulnerabilityScanning` | Profile-dependent | Go Binary | Optional | `Healthy` |
| `bughunter` | BugHunter AI Security Engine | `pinned-v1.0.0` | `AiAssistedHunting`, `ReportGeneration` | **Yes** | Python 3.11+ CLI | `GROQ_API_KEY` (Required) | `Healthy` |

---

## Tool Capability Definitions

- **SubdomainEnumeration**: Passive and active subdomain discovery across target domain assets.
- **DnsResolution**: Mass DNS resolution and record verification.
- **HttpProbing**: Fast HTTP/HTTPS web server probing and response header inspection.
- **UrlCrawling**: Deep web spidering and JavaScript endpoint extraction.
- **VulnerabilityScanning**: Template-based and signature security vulnerability scanning.
- **AiAssistedHunting**: LLM-assisted security vulnerability hypothesis generation and verification.
- **ReportGeneration**: Normalized security assessment artifact and finding report generation.
