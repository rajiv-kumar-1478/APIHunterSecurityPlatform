# Hosted Scanner Worker Operations Guide

## Overview

The `IScanWorker` pipeline manages hosted scan job execution, worker heartbeats, secret lease management, and artifact persistence.

---

## Worker Execution Flow

1. **Claiming**: Worker claims queued job using PostgreSQL `FOR UPDATE SKIP LOCKED`.
2. **Authorization Re-Check**: Re-verifies target scope authorization and requesting user permissions before invoking any tools.
3. **Secret Leasing**: Acquires temporary in-memory secret lease via `IScanProviderSecretStore.AcquireLeaseAsync()`.
4. **Tool Execution**: Dispatches execution request to `IScanProvider`.
5. **Artifact Capture**: Stores tool logs and structured execution JSON into object storage.
6. **Lease Cleanup**: Disposes `ProviderSecretLease`, clearing raw keys from worker memory.
