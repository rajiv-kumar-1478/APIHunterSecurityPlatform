# Output Parser Contract & Resource Limits

## Parser Design Rules

Each scanner adapter must have a dedicated parser class (e.g. `SemgrepOutputParser`, `NucleiOutputParser`) implementing bounded, streaming parsing of raw container output.

```text
Raw Container stdout/stderr
            │
            ▼
┌───────────────────────────────┐
│   Streaming Line/JSON Reader  │
├───────────────────────────────┤
│ 1. Size Guard (10 MiB limit)  │
│ 2. Max Candidates (1,000 cap) │
│ 3. Max Evidence (16 KiB cap)  │
│ 4. Malformed Line Resilience  │
└──────────────┬────────────────┘
               │
               ▼
     ToolParsedOutputResult
   ├── FindingCandidate[]
   └── ScannerCoverage
```

---

## Mandatory Resource Ceilings

| Constant | Bound | Purpose |
|---|---|---|
| **`MaxRawOutputBytes`** | `10 * 1024 * 1024` (10 MiB) | Prevents runaway CLI stdout from causing Out-Of-Memory (OOM). |
| **`MaxCandidates`** | `1,000` | Caps the number of findings emitted per scan job. |
| **`MaxEvidenceBytes`** | `16 * 1024` (16 KiB) | Prevents bloated HTTP request/response payloads in finding evidence. |

---

## Scanner Coverage Contract

The parser must construct a `ScannerCoverage` instance recording:

```csharp
public sealed record ScannerCoverage(
    int EndpointsDiscovered,
    int ParametersExtracted,
    int AssetsProbed,
    int JavaScriptFilesDiscovered,
    bool CoverageTruncated,
    string? CoverageTruncationReason,
    int MalformedRecordCount,
    bool OutputTruncated
);
```

- **`MalformedRecordCount`**: Count of corrupt JSON lines safely skipped.
- **`CoverageTruncated`**: Set to `true` if `MaxCandidates` was hit during parsing.
- **`OutputTruncated`**: Set to `true` if `MaxRawOutputBytes` was exceeded.
