# C Buffer Analysis Flowcharts

## End-to-end data flow

```mermaid
flowchart LR
    UI[Streamlit analysis tab] --> Runner[Python analysis runner]
    Runner --> Model[Bounded formal state model]
    Runner --> GCC[GCC warnings and analyzer]
    Runner --> CBMC[Optional CBMC harness]
    Runner --> ASAN[AddressSanitizer and UBSan]
    Runner --> Fuzz[Deterministic mutation fuzzer]
    Model --> Report[JSON security report]
    GCC --> Report
    CBMC --> Report
    ASAN --> Report
    Fuzz --> Report
    Report --> UI
```

## Buffer-copy state analyzer

```mermaid
stateDiagram-v2
    [*] --> S0_INPUT
    S0_INPUT --> S1_VALIDATE: receive source and signed length
    S1_VALIDATE --> S2_REJECT: length < 0 OR length > source_size OR length > destination_capacity
    S1_VALIDATE --> S3_COPY: length >= 0 AND length <= source_size AND length <= destination_capacity
    S2_REJECT --> S4_DONE: return error
    S3_COPY --> S4_DONE: memcpy validated byte range
    S4_DONE --> [*]
```

The vulnerable teaching example checks only `length > destination_capacity`.
It therefore allows a negative signed length to reach `memcpy`, where the
conversion to `size_t` produces an invalidly large copy length. The corrected
implementation rejects negative lengths before conversion and checks both
source and destination bounds.

## Analysis sequence

```mermaid
flowchart TD
    A[Validate model and bounded constraints] --> B[Compile both C implementations with GCC analyzer]
    B --> C{Is CBMC installed?}
    C -->|yes| D[Check pointer safety and bounds for both harnesses]
    C -->|no| E[Record CBMC as unavailable]
    D --> F[Run vulnerable and safe binaries under ASan and UBSan]
    E --> F
    F --> G[Fuzz corrected C implementation with a reproducible seed]
    G --> H[Write JSON report with findings and tool availability]
```
