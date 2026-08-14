# Scanner Runtime Sandbox Deployment Guide (Local Docker, Render & Railway)

This document describes the deployment architecture and configuration for the APIHunter Security Scanner Runtime Sandbox across local environments and cloud providers (Render & Railway).

---

## 1. Architecture Overview

```
                      GenericScanWorker
                             │
                             ▼
                   IScannerRuntimeSandbox
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
       LocalDocker      CloudManaged      UnsafeLocal
                         Container         Process
      (docker run)     (Render/Railway)   (Dev Only)
            │                │
            ▼                ▼
     Enforced Egress Gateway (Dedicated Egress Boundary)
            │
            ├── Approved Target IP ──────► ALLOW (Target)
            ├── Private IP (RFC 1918) ───► DENY
            ├── IMDS (169.254.169.254) ──► DENY
            ├── Loopback (127.0.0.1) ────► DENY
            └── Unapproved IPs ──────────► DENY
```

---

## 2. Runtime Modes

### `LocalDocker` (Default for local development / Docker-enabled VMs)
- **Mechanism**: Spawns isolated container processes via `docker run` using argument boundaries (`ProcessStartInfo.ArgumentList`).
- **Isolation Controls**:
  - `--read-only`: Read-only root filesystem.
  - `--cap-drop=ALL`: Drops all Linux kernel capabilities.
  - `--security-opt=no-new-privileges:true`: Prevents privilege escalation.
  - `--network=apihunter-sandbox-net`: Attached strictly to dedicated sandbox network.
  - `--env=HTTP_PROXY=...`, `--env=HTTPS_PROXY=...`, `--env=NO_PROXY=""`: Mandatory egress gateway routing (no local bypasses).
  - CPU limit (`--cpus`), Memory limit (`--memory`), PID limit (`--pids-limit`).
  - Image provenance pin: `{ContainerImageRepository}@{ContainerImageDigest}` (e.g. `ghcr.io/apihunter-security/subfinder@sha256:...`).

### `CloudManagedContainer` (Render Private Services & Railway Internal Mesh)
- **Mechanism**: Cloud-native decoupled service/worker architecture.
  - Render background workers and Railway services run containerized workloads directly.
  - Workers do NOT require Docker-in-Docker (`docker.sock`).
  - Workloads dispatch to dedicated scanner private services communicating over private meshes with mutual authentication (`X-Scanner-Service-Key`).
- **Egress Boundary**:
  - Cloud deployments configure a dedicated `EnforcedEgressGateway` service.
  - `ScannerRuntimeOptions.EgressGatewayEndpoint` is set to the cloud gateway service URL (e.g. `http://egress-gateway.internal:8888`).

### `UnsafeLocalProcessFallback` (Dev Test Harness Only)
- Strictly disabled in production. Used only for mocked unit testing where container runtimes are unavailable.

---

## 3. Configuration Reference (`appsettings.json` / Environment Variables)

| Configuration Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `ScannerRuntime:RuntimeMode` | `string` | `LocalDocker` | `LocalDocker` or `CloudManagedContainer` |
| `ScannerRuntime:EgressGatewayMode` | `string` | `EnforcedGateway` | `EnforcedGateway`, `IsolatedNetwork`, `None` |
| `ScannerRuntime:EgressGatewayEndpoint` | `string` | `http://127.0.0.1:8888` | Mandatory gateway endpoint in `EnforcedGateway` mode |
| `ScannerRuntime:EgressNetworkName` | `string` | `apihunter-sandbox-net` | Dedicated Docker sandbox network name |
| `ScannerRuntime:EnforceImageProvenance` | `bool` | `true` | Requires immutable SHA-256 digest pinning |
| `ScannerRuntime:TrustedImageRegistries` | `string[]` | `["ghcr.io/apihunter-security", ...]` | Allowlisted container registries |
| `ScannerRuntime:MaxCpuCores` | `double` | `2.0` | Maximum CPU cores per container |
| `ScannerRuntime:MaxMemoryBytes` | `long` | `1073741824` | Maximum memory (1 GiB) |
| `ScannerRuntime:MaxPids` | `int` | `100` | Maximum process limit |
| `ScannerRuntime:ExecutionTimeout` | `TimeSpan` | `00:10:00` | Maximum container execution timeout |

---

## 4. Verification & Operational Health Check

Inspect runtime health in real-time via API:
```http
GET /api/v1/security/scans/runtime/health
Authorization: Bearer <token>
```

Response:
```json
{
  "runtime": {
    "mode": "LocalDocker",
    "available": true,
    "version": "Docker CLI Active"
  },
  "provenance": {
    "imageDigestRequired": true,
    "trustedRegistries": [
      "ghcr.io/apihunter-security",
      "docker.io/apihunter",
      "quay.io/apihunter"
    ]
  },
  "egress": {
    "mode": "EnforcedGateway",
    "enforced": true,
    "gatewayHealthy": true,
    "gatewayEndpoint": "http://127.0.0.1:8888"
  },
  "limits": {
    "cpuCores": 2.0,
    "memoryBytes": 1073741824,
    "pids": 100,
    "scratchBytes": 524288000,
    "timeoutSeconds": 600
  },
  "activeJobsCount": 0,
  "readyForScans": true,
  "lastHealthCheckUtc": "2026-08-14T07:50:00Z"
}
```
If `readyForScans == false`, scan job submission is rejected fail-closed until all security components are healthy.
