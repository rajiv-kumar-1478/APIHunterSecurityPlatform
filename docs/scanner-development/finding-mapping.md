# Finding Candidate Mapping & Canonical Fingerprinting

Parsers translate bounded scanner observations into platform-owned `FindingCandidate` records. Raw scanner output is never a finding by itself.

## Ingestion authority

```text
bounded parser output
    ▼
FindingCandidate + immutable tool provenance
    ▼
EvidenceSanitizer
  - redact authorization/cookies/tokens/private keys
  - bound JSON/evidence size
    ▼
tenant/repository/target-qualified fingerprint and deduplication
    ▼
authoritative finding, evidence, observation, risk, and audit persistence
```

## Mapping rules

- Preserve tool key/version/image digest and rule/template identifiers as provenance; do not expose raw secrets or unbounded output.
- Normalize severity, finding type, endpoint, method, identifiers, and timestamps through platform rules.
- Reject malformed or out-of-scope targets before persistence.
- Static/SAST/recon observations describe potential or code-level conditions and must not claim confirmed exploitability.
- Active verification may claim a confirmed dynamic condition only when an **operational, authorized runtime** produced reproducible sanitized evidence against the registered tenant target.
- BugHunter is currently unavailable and therefore cannot emit authoritative active findings. Planned provider capability must not be represented as observed evidence.
- AI output remains advisory and cannot create or upgrade an authoritative finding without deterministic evidence.

## Deduplication

Fingerprints must include the durable ownership/asset boundary and canonical security identity needed to prevent cross-tenant or cross-target mutation. Repeated observations update observation/provenance state without erasing finding lifecycle history.
