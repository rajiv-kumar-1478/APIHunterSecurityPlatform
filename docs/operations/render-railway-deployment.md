# Scanner-Enabled Deployment Acceptance Guide

## Status

This is a **proposed scanner-enabled reference architecture**, not the current deployment state. The checked-in Compose deployment runs PostgreSQL, API, worker, and frontend with scanner execution, scan consumption, and campaign scheduling disabled/fail-closed.

Current verified configuration properties:
- API, worker, and frontend images run as non-root users.
- Worker exposes no public port and joins private backend plus outbound networks.
- API and worker share persisted ASP.NET Core Data Protection keys and the same application name.
- PostgreSQL, API, and frontend have health checks.

Live Compose/image validation is currently blocked because Docker is unavailable on the validation machine.

## Required scanner-enabled topology

```text
Public frontend/API
        │ private authenticated control plane
        ▼
Tenant-configured worker
        │
        ▼
Dedicated non-root scanner executor
        │ all target traffic
        ▼
Enforced egress boundary
   ├─ authorized target IPs: allow
   └─ private/link-local/IMDS/unapproved: deny
```

The scanner executor and egress gateway must be distinct, authoritative services. Application-level destination checks alone are not a physical isolation boundary.

## Required configuration

| Setting | Requirement |
|---|---|
| `ScannerRuntime__RuntimeMode` | Explicit supported executor mode; never implicit host execution |
| `ScannerRuntime__EgressGatewayMode` | Enforced gateway mode |
| `ScannerRuntime__EgressGatewayEndpoint` | Private authenticated endpoint |
| `ScannerRuntime__HostedScannerServiceEndpoint` | Private executor endpoint for managed mode |
| `ScannerRuntime__HostedScannerServiceKey` | Secret-managed authentication material |
| `ScannerRuntime__EnforceImageProvenance` | `true` |
| CPU/memory/PID/timeout settings | Finite and enforced by the executor |
| Tool images | Exact repository plus immutable `sha256:` digest; mutable tags such as `:latest` are forbidden |

## Render/Railway acceptance

Render or Railway may be used only when the deployment supplies:
1. a private worker and private scanner service;
2. authenticated control-plane requests;
3. a separately enforced outbound gateway with private/link-local/IMDS denial;
4. digest-pinned scanner and gateway images;
5. non-root, read-only, capability-dropped scanner containers with resource limits;
6. durable shared Data Protection keys for API/worker;
7. truthful readiness that remains false until every boundary is healthy.

Any `render.yaml` or Railway service definition is an environment-specific artifact and must be reviewed separately. No such checked-in artifact currently proves this topology.

## Live validation gate

Before changing runtime mode from `Disabled`:
- validate Compose/config rendering;
- build API, worker, and frontend images and inspect their effective users;
- prove scanner containers are non-root, read-only, capability-dropped, and resource-limited;
- prove allowed target egress succeeds and private/link-local/IMDS/unapproved egress fails;
- prove cancellation kills the exact process/container tree;
- prove missing credentials, gateway, image digest, or provider contract fails closed;
- run PostgreSQL distributed scheduler races against a real database.

If Docker/PostgreSQL is unavailable, record these checks as **blocked**, not passed, and keep scanner execution disabled.
