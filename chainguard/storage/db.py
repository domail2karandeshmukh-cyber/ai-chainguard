"""SQLite connection and schema.

The database is an INDEX, not the source of truth for integrity: signed envelopes on
disk are. The verifier recomputes everything from files and only reads two things
from the DB: the trust store (signers) and revocation state.

LIMIT OF THIS VERSION: the DB is not tamper-evident. Someone with write access could edit
``last_status`` or delete event rows. Verification is unaffected (status is always
recomputed), but the audit trail is weakened. Production: append-only log anchored
in a transparency service, trust store distributed as a signed, pinned file.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS signers (
    key_id          TEXT PRIMARY KEY,
    identity        TEXT NOT NULL,
    role            TEXT NOT NULL,
    public_key_b64  TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    revoked_at      TEXT,
    revoked_reason  TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id     TEXT PRIMARY KEY,
    artifact_name   TEXT NOT NULL,
    artifact_type   TEXT NOT NULL,
    version         TEXT NOT NULL,
    pipeline_stage  TEXT NOT NULL,
    subject_uri     TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    merkle_root     TEXT,
    manifest_digest TEXT NOT NULL UNIQUE,
    envelope_path   TEXT NOT NULL,
    signer_key_id   TEXT NOT NULL REFERENCES signers(key_id),
    created_at      TEXT NOT NULL,
    last_status     TEXT,
    last_verified_at TEXT,
    revoked         INTEGER NOT NULL DEFAULT 0,
    revoked_reason  TEXT,
    revoked_at      TEXT
);

-- Copy of the parent links from the signed payloads, for fast graph queries.
-- Foreign keys are declared for documentation but not enforced: an attack scenario
-- deletes a parent row on purpose, and the verifier must detect that itself.
CREATE TABLE IF NOT EXISTS artifact_parents (
    child_id               TEXT NOT NULL REFERENCES artifacts(artifact_id),
    parent_id              TEXT NOT NULL REFERENCES artifacts(artifact_id),
    parent_manifest_digest TEXT NOT NULL,
    relation               TEXT NOT NULL,
    PRIMARY KEY (child_id, parent_id)
);

CREATE TABLE IF NOT EXISTS verification_runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id     TEXT NOT NULL,
    context         TEXT NOT NULL,
    overall_status  TEXT NOT NULL,
    checks_json     TEXT NOT NULL,
    duration_ms     REAL NOT NULL,
    run_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    event_type      TEXT NOT NULL,
    artifact_id     TEXT,
    message         TEXT NOT NULL,
    details_json    TEXT
);

CREATE TABLE IF NOT EXISTS metrics (
    metric_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    operation       TEXT NOT NULL,
    artifact_id     TEXT,
    size_bytes      INTEGER,
    duration_ms     REAL NOT NULL,
    extra_json      TEXT
);

CREATE INDEX IF NOT EXISTS idx_parents_parent ON artifact_parents(parent_id);
CREATE INDEX IF NOT EXISTS idx_runs_artifact ON verification_runs(artifact_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(ts);
CREATE INDEX IF NOT EXISTS idx_metrics_op ON metrics(operation);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with dict-like rows. One short-lived connection per operation
    keeps the code thread-safe for FastAPI's thread pool."""
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # concurrent readers (dashboard) + one writer
    conn.execute("PRAGMA synchronous=NORMAL")  # durable with WAL; avoids an fsync per commit
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(db_path: str | Path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
