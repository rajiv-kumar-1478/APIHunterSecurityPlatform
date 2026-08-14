# Scanner Runtime Sandbox Deployment Guide (Render, Railway & Local Docker)

This document specifies the deployment architecture, configuration contracts, and secret isolation guarantees for the APIHunter Security Scanner Runtime Sandbox across primary cloud hosting targets (Render and Railway) and local development/CI environments.

---

## 1. Deployment Model Architecture (Option A)

```
                            ┌──────────────────────────────────────┐
                            │    Web Dashboard / API Service       │
                            │  (Render Web Service / Railway App)  │
                            └──────────────────┬───────────────────┘
                                               │
                                               ▼
                            ┌──────────────────────────────────────┐
                            │      GenericScanWorker Service       │
                            │    (Render Worker / Railway Worker)  │
                            └──────────────────┬───────────────────┘
                                               │
                                               │ X-Scanner-Service-Key (Private Mesh)
                                               ▼
                            ┌──────────────────────────────────────┐
                            │   Dedicated Scanner Private Service  │
                            │  (Render Private / Railway Private)  │
                            └──────────────────┬───────────────────┘
                                               │
                                               │ All Outbound Traffic
                                               ▼
                            ┌──────────────────────────────────────┐
                            │       Enforced Egress Gateway        │
                            │  (Dedicated Proxy Network Boundary)  │
                            └──────────────────┬───────────────────┘
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
             Approved Target IP                               Unapproved IP / Private / IMDS
                 [ ALLOW ]                                              [ DENY ]
```

---

## 2. Configuration Contracts Matrix

### Configuration Reference (`appsettings.json` / Environment Variables)

| Variable Name | Required | Default (Local Docker) | Render / Railway Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ScannerRuntime__RuntimeMode` | **Yes** | `LocalDocker` | `CloudManagedContainer` | Execution runtime mode. |
| `ScannerRuntime__EgressGatewayMode` | **Yes** | `EnforcedGateway` | `EnforcedGateway` | Active network proxy enforcement mode. |
| `ScannerRuntime__EgressGatewayEndpoint` | **Yes** | `http://127.0.0.1:8888` | `http://egress-gateway.internal:8888` | Gateway service endpoint. |
| `ScannerRuntime__HostedScannerServiceEndpoint` | Cloud Only | *(empty)* | `http://scanner-service.internal:8080` | Private scanner service endpoint. |
| `ScannerRuntime__HostedScannerServiceKey` | Cloud Only | *(empty)* | `[SECRET_ENV_VAR]` | Pre-shared key for scanner authentication. |
| `ScannerRuntime__EnforceImageProvenance` | **Yes** | `true` | `true` | Mandates pinned SHA-256 image digests. |
| `ScannerRuntime__MaxCpuCores` | Optional | `2.0` | `2.0` | Container CPU core limit. |
| `ScannerRuntime__MaxMemoryBytes` | Optional | `1073741824` | `1073741824` | Container memory limit (1 GiB). |
| `ScannerRuntime__MaxPids` | Optional | `100` | `100` | Process limit per container. |

---

## 3. Render Deployment Specification (`render.yaml`)

```yaml
services:
  # 1. Platform API & Dashboard
  - type: web
    name: apihunter-platform-api
    runtime: dotnet
    plan: standard
    buildCommand: dotnet publish src/Platform.Api -c Release -o out
    startCommand: ./out/Platform.Api
    envVars:
      - key: ASPNETCORE_ENVIRONMENT
        value: Production
      - key: ScannerRuntime__RuntimeMode
        value: CloudManagedContainer
      - key: ScannerRuntime__HostedScannerServiceEndpoint
        fromService:
          type: pserv
          name: apihunter-scanner-service
          property: hostport
      - key: ScannerRuntime__HostedScannerServiceKey
        generateValue: true
      - key: ScannerRuntime__EgressGatewayEndpoint
        fromService:
          type: pserv
          name: apihunter-egress-gateway
          property: hostport

  # 2. Dedicated Scanner Private Service (No Public Route)
  - type: pserv
    name: apihunter-scanner-service
    runtime: image
    image:
      url: ghcr.io/apihunter-security/scanner-service:latest
    envVars:
      - key: SCANNER_SERVICE_KEY
        fromService:
          type: web
          name: apihunter-platform-api
          envVarKey: ScannerRuntime__HostedScannerServiceKey
      - key: HTTP_PROXY
        fromService:
          type: pserv
          name: apihunter-egress-gateway
          property: hostport
      - key: HTTPS_PROXY
        fromService:
          type: pserv
          name: apihunter-egress-gateway
          property: hostport
      - key: NO_PROXY
        value: ""

  # 3. Dedicated Egress Gateway Boundary
  - type: pserv
    name: apihunter-egress-gateway
    runtime: image
    image:
      url: ghcr.io/apihunter-security/egress-gateway:latest
    envVars:
      - key: EGRESS_ALLOW_PRIVATE_IPS
        value: "false"
      - key: EGRESS_ALLOW_IMDS
        value: "false"
```

---

## 4. Railway Deployment Specification (`railway.json` / Service Mesh)

In Railway, services communicate over the internal private network (`*.railway.internal`):

1. **`apihunter-api` Service**:
   - `ScannerRuntime__RuntimeMode` = `CloudManagedContainer`
   - `ScannerRuntime__HostedScannerServiceEndpoint` = `http://scanner-service.railway.internal:8080`
   - `ScannerRuntime__HostedScannerServiceKey` = `${{ secrets.SCANNER_SERVICE_KEY }}`
   - `ScannerRuntime__EgressGatewayEndpoint` = `http://egress-gateway.railway.internal:8888`
2. **`scanner-service` Service**:
   - Private service exposing port `8080`.
   - `X-Scanner-Service-Key` validation middleware enabled.
   - Outbound HTTP/HTTPS proxy configured to `http://egress-gateway.railway.internal:8888` with `NO_PROXY=""`.

---

## 5. Local Docker Development Specification

For local development and CI test runners:
```bash
# Start local egress gateway and sandbox network
docker network create apihunter-sandbox-net
docker run -d --name apihunter-local-gateway --network apihunter-sandbox-net -p 127.0.0.1:8888:8888 ghcr.io/apihunter-security/egress-gateway:latest
```
Configuration in `appsettings.Development.json`:
```json
{
  "ScannerRuntime": {
    "RuntimeMode": "LocalDocker",
    "EgressGatewayMode": "EnforcedGateway",
    "EgressNetworkName": "apihunter-sandbox-net",
    "EgressGatewayEndpoint": "http://127.0.0.1:8888",
    "EnforceImageProvenance": true
  }
}
```

---

## 6. Secret Sanitization & Observability Guarantee

- **Zero Plaintext Exposure**: `HostedScannerServiceKey` is never returned in `GET /api/v1/security/scans/runtime/health` or rendered on the dashboard.
- **Fail Closed**: If `HostedScannerServiceEndpoint` or `HostedScannerServiceKey` is missing or unauthenticated, the runtime health probe marks `Available: false` and `ReadyForScans: false`, preventing unmonitored job creation.
