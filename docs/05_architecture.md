# Architecture

One core library (`chainguard/`) holds all security logic. The CLI, FastAPI backend, ML pipeline, deployment gateway, attack scripts and CI call that same library, so there is exactly one implementation of hashing, signing and verification. The dashboard uses only the HTTP API.

## 1. Overall system architecture

```mermaid
flowchart LR
  subgraph Clients
    CLI[cli/main.py]
    ML[ml_pipeline/<br/>PyTorch]
    CI[GitHub Actions]
    DASH[dashboard/<br/>Streamlit]
  end
  subgraph Backend[api/ FastAPI]
    API[REST routes]
  end
  subgraph Core[chainguard/ core library]
    HASH[crypto/hashing<br/>SHA-256]
    CAN[crypto/canonical]
    SIGN[crypto/signing + keys<br/>Ed25519]
    MAN[manifest/<br/>models + builder]
    MER[provenance/merkle]
    POL[provenance/policy]
    SEM[semantic/data_checks]
    VER[verification/verifier<br/>V0-V9]
    REG[registry]
    TRU[trust]
  end
  subgraph Storage[Workspace]
    ENV[(artifacts/manifests<br/>signed envelopes)]
    FILES[(data/ + artifacts/models)]
    DB[(SQLite index)]
    KEYS[(keys/ 0600)]
  end
  GW[deployment/gateway]
  DASH -->|HTTP| API
  CLI --> REG & VER
  ML --> REG & VER
  CI --> CLI & ML
  API --> REG & VER & GW
  GW --> VER
  REG --> HASH & MER & SEM & MAN & POL & TRU
  MAN --> CAN & SIGN
  VER --> HASH & MER & CAN & SIGN & POL
  REG --> ENV & DB
  VER --> ENV & FILES & DB
  TRU --> KEYS & DB
```

## 2. AI supply-chain lifecycle with attestation points

```mermaid
flowchart LR
  S0[Data collection<br/>sklearn digits] --> S1[Stage 1<br/>datasets attested<br/>data_steward]
  S1 --> S2[Stage 2<br/>base model trained<br/>training_pipeline]
  S1 --> S3
  S2 --> S3[Stage 3<br/>fine-tuned model<br/>training_pipeline]
  S3 --> S4{Stage 4<br/>deployment gateway}
  S4 -->|VERIFIED| DEP[Signed deployment record<br/>release root]
  S4 -->|FAILED / WARNING| BLOCK[Blocked<br/>DEPLOYMENT_BLOCKED event]
```

## 3. Artifact attestation sequence

```mermaid
sequenceDiagram
  actor U as Caller (pipeline / CLI / API)
  participant R as Registry
  participant V as Verifier
  participant H as Hashing + Merkle
  participant S as Semantic checks
  participant K as Trust store + Ed25519
  participant W as Envelope files + SQLite
  U->>R: register(file, type, stage, role, parents)
  loop each parent
    R->>V: verify(parent) - refuse if FAILED
    R->>W: read parent payload, compute manifest digest
  end
  R->>R: policy check (type, stage, role, parent types)
  R->>K: load role key, check it matches trusted key id
  R->>H: SHA-256 (streamed) [+ row Merkle tree for CSV]
  R->>S: content checks (datasets) BEFORE signing
  R->>R: build payload (subject, parents' digests, provenance, checks, signer)
  R->>K: sign canonical_json(payload)
  R->>W: write envelope + leaves sidecar, index row, event, metrics
  R-->>U: artifact_id, manifest_digest
```

## 4. Verification sequence

```mermaid
sequenceDiagram
  participant C as Gateway / API / CI
  participant V as Verifier
  participant F as Files
  participant D as SQLite (trust store, revocation)
  C->>V: verify(artifact_id)
  V->>F: V0 load envelope (raw JSON, schema, id matches)
  V->>F: V1 recompute SHA-256 + size
  V->>F: V2 recompute row Merkle root, diff via authenticated sidecar
  V->>D: V3/V4 public key, revocation, role, identity
  V->>V: V3 Ed25519 verify over canonical payload
  V->>F: V5 load parents, recompute their manifest digests
  V->>V: V6 recurse into every parent (memoised)
  V->>D: V7 revocation of artifact + ancestors, index row exists
  V->>V: V8 policy, V9 semantic flags (own + inherited)
  V->>D: store run, status, metrics, events
  V-->>C: VERIFIED / WARNING / FAILED + per-check report
```

## 5. Attack-detection workflow

```mermaid
flowchart TD
  A[Artifact presented] --> B{V1/V2 bytes and rows<br/>match signed values?}
  B -- no --> F1[FAILED: content tampered<br/>Scenarios A, B, E1]
  B -- yes --> C{V3/V4 valid signature<br/>by trusted key in role?}
  C -- no --> F2[FAILED: invalid or untrusted signature<br/>Scenario D]
  C -- yes --> D{V5/V6 parents exist,<br/>digests match, ancestors pass?}
  D -- no --> F3[FAILED: broken provenance<br/>Scenario C]
  D -- yes --> E{V7 revoked anywhere<br/>in the chain?}
  E -- yes --> F4[FAILED: revoked]
  E -- no --> P{V8 policy satisfied?}
  P -- no --> F5[FAILED: policy violation<br/>C4]
  P -- yes --> W{V9 content flagged<br/>here or upstream?}
  W -- yes --> WARN[WARNING: integrity intact,<br/>content suspicious - E3]
  W -- no --> OK[VERIFIED - still not proof of safety<br/>E2, E4]
```

## 6. Deployment view

```mermaid
flowchart LR
  subgraph compose[docker compose]
    P[pipeline<br/>one-shot] --> VOL[(volume: workspace)]
    A[api :8000] --- VOL
    D[dashboard :8501] -->|HTTP| A
  end
  U[Browser] --> D
  U --> A
```

## 7. Key design decisions

| Decision | Alternatives | Reason |
| --- | --- | --- |
| Envelopes on disk are the source of truth; SQLite is an index | DB as truth | CI and auditors can verify from files; DB tampering cannot fake integrity |
| Sign the whole canonical payload | Sign only the file hash | Prevents swapping stage, parents, version, role around a valid hash |
| Parents referenced by manifest digest | By artifact id only | Hash-linking makes history rewrites detectable (C2) |
| Recursive verification at every use | Trust a parent's stored status | Stored status can be edited; recomputation costs a few ms |
| Semantic flags → WARNING only | Fail on any flag | Keeps heuristics from being mistaken for cryptographic proof |
| Role-bound keys + YAML policy | One signing key | Limits blast radius of one key compromise |
