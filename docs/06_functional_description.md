# Functional description

What AI-ChainGuard does, from a user's point of view.

## Actors

| Actor | Uses | Typical actions |
| --- | --- | --- |
| Data steward | CLI / API | Register and attest datasets |
| ML engineer / training pipeline | `ml_pipeline`, CLI | Train, fine-tune, attest models |
| Release manager | Dashboard, CLI | Verify, deploy, revoke |
| Security analyst | Dashboard | Inspect chain, events, metrics; run attack lab |
| CI system | GitHub Actions | Attest and gate releases automatically |

## Use cases

| ID | Use case | Result |
| --- | --- | --- |
| UC1 | Initialise keys (`keys init`) | One Ed25519 key per role; public keys in the trust store |
| UC2 | Register a dataset | Hash, Merkle root, content checks, signed manifest, index entry |
| UC3 | Train and register a model | Parent dataset verified first; model signed with link to dataset |
| UC4 | Fine-tune and register | Two parents (base model, fine-tune dataset), both verified |
| UC5 | Verify any artifact | VERIFIED / WARNING / FAILED with a report of checks V0–V9 and all ancestors |
| UC6 | Deploy through the gateway | Only VERIFIED (or WARNING with logged override) models load; signed deployment record |
| UC7 | Revoke an artifact or key | Artifact and all descendants fail V7 / V4 from then on |
| UC8 | View provenance chain | Graph coloured by status; signed manifest and unsigned index state side by side |
| UC9 | Demonstrate tampering | Attack lab: modify a file live, see FAILED, restore |
| UC10 | Run attack scenarios A–E | JSON results, summary table, figures |
| UC11 | Review security events | Filterable log, CSV export |
| UC12 | Review performance | Per-operation statistics, overhead vs training |

## Status semantics

| Status | Meaning | Gateway default |
| --- | --- | --- |
| VERIFIED | All checks passed; no content flag here or upstream | Deploy |
| WARNING | Integrity intact; a content check flagged data here or upstream | Block (override possible, logged) |
| FAILED | At least one integrity, trust, provenance, revocation or policy check failed | Block |

## CLI reference

```
python -m cli.main keys init [--rotate]        python -m cli.main list
python -m cli.main keys list                   python -m cli.main events [--limit N]
python -m cli.main keys revoke KEY_ID --reason TEXT
python -m cli.main register FILE --type T --stage S --role R [--parent ID:relation] [--version V] [--no-checks]
python -m cli.main verify ID [--file CANDIDATE] [--json]     # exit 0 VERIFIED, 2 WARNING, 1 FAILED
python -m cli.main revoke ID --reason TEXT
python -m cli.main mvp-demo
```

## API reference (http://localhost:8000/docs)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /health | Status, workspace, counts |
| GET | /artifacts, /artifacts/{id}, /artifacts/{id}/lineage, /graph, /signers | Read registry |
| POST | /artifacts | Register (path inside workspace) |
| POST | /artifacts/{id}/revoke | Revoke |
| POST | /verify/{id} · GET /verify/runs | Verify, history |
| POST | /deploy/{id} | Deployment gateway |
| GET | /events, /metrics, /metrics/summary | Evidence |
| POST | /demo/tamper/{id}, /demo/restore/{id} | Live demo (CHAINGUARD_DEMO_MODE=1) |
| POST | /attacks/{A-E} · GET /attacks/results | Scenario runs |

## Dashboard pages

Overview · Provenance Chain · Verify Artifact (verify, deploy, revoke) · Attack Lab · Security Events · Metrics.
