# Sandbox Execution & Isolation Requirements

## Runtime Environment (`IScannerRuntimeSandbox`)

All scanner containers execute inside the Phase 8 Docker/Container sandbox under strict security constraints.

---

## Security Invariants

1. **Dropped Linux Capabilities**:
   - `cap_drop = ["ALL"]`
   - Scanners cannot perform raw socket manipulation or kernel privilege escalation.

2. **Read-Only Root Filesystem**:
   - `read_only = true`
   - Scanners can only write temporary output to a memory-backed `/tmp` mount (`tmpfs: size=64M`).

3. **No Root Execution**:
   - `user = "10001:10001"` (non-root UID).

4. **Resource Bounds**:
   - `MemoryLimit`: Max 1.5 GiB per container.
   - `CpuQuota`: Max 2.0 cores.
   - `TimeoutSeconds`: Defaults to 300s (5 minutes). Hard killed upon deadline expiry.

5. **Network Egress Gateway**:
   - Scanners interact with targets strictly through the authorized platform proxy or sandbox egress gateway.
   - Local link-local (`169.254.169.254`) and internal VPC metadata services are blocked.
