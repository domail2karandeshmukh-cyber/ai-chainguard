"""Data-access layer over the SQLite index.

All SQL lives here; the rest of the code calls plain Python methods. Queries use
parameter binding (``?``) everywhere, never string formatting, to avoid SQL injection
through artifact names or API input.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chainguard.manifest.models import ManifestBody
from chainguard.storage.db import connect, init_db


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row(r) -> dict[str, Any] | None:
    return dict(r) if r is not None else None


class Repository:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        init_db(self.db_path)

    @contextmanager
    def _conn(self) -> Iterator:
        conn = connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- signers / trust store ---------------------------------------------------
    def add_signer(self, key_id: str, identity: str, role: str, public_key_b64: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO signers (key_id, identity, role, public_key_b64, created_at) VALUES (?,?,?,?,?)",
                (key_id, identity, role, public_key_b64, _now()),
            )

    def get_signer(self, key_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            return _row(c.execute("SELECT * FROM signers WHERE key_id = ?", (key_id,)).fetchone())

    def list_signers(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM signers ORDER BY role, created_at")]

    def active_signer_for_role(self, role: str) -> dict[str, Any] | None:
        with self._conn() as c:
            return _row(c.execute(
                "SELECT * FROM signers WHERE role = ? AND revoked_at IS NULL "
                "ORDER BY created_at DESC LIMIT 1", (role,)).fetchone())

    def revoke_signer(self, key_id: str, reason: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE signers SET revoked_at = ?, revoked_reason = ? WHERE key_id = ? AND revoked_at IS NULL",
                (_now(), reason, key_id))
            return cur.rowcount > 0

    # ---- artifacts -----------------------------------------------------------------
    def add_artifact(self, body: ManifestBody, manifest_digest: str, envelope_path: str) -> None:
        merkle_root = body.subject.merkle.root if body.subject.merkle else None
        with self._conn() as c:
            c.execute(
                """INSERT INTO artifacts (artifact_id, artifact_name, artifact_type, version, pipeline_stage,
                       subject_uri, sha256, size_bytes, merkle_root, manifest_digest, envelope_path,
                       signer_key_id, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (body.artifact_id, body.artifact_name, body.artifact_type, body.version, body.pipeline_stage,
                 body.subject.uri, body.subject.sha256, body.subject.size_bytes, merkle_root,
                 manifest_digest, envelope_path, body.signer.key_id, body.created_at),
            )
            for p in body.parents:
                c.execute(
                    "INSERT OR REPLACE INTO artifact_parents (child_id, parent_id, parent_manifest_digest, relation) "
                    "VALUES (?,?,?,?)",
                    (body.artifact_id, p.artifact_id, p.manifest_digest, p.relation),
                )

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            return _row(c.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone())

    def find_artifacts(self, name: str) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM artifacts WHERE artifact_name = ? ORDER BY created_at DESC", (name,))]

    def list_artifacts(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM artifacts ORDER BY created_at, rowid")]

    def delete_artifact(self, artifact_id: str) -> None:
        """Only used by attack simulations (Scenario C) to remove a provenance link."""
        with self._conn() as c:
            c.execute("DELETE FROM artifacts WHERE artifact_id = ?", (artifact_id,))

    def get_parent_links(self, child_id: str) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM artifact_parents WHERE child_id = ?", (child_id,))]

    def get_child_links(self, parent_id: str) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM artifact_parents WHERE parent_id = ?", (parent_id,))]

    def all_links(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM artifact_parents")]

    def set_status(self, artifact_id: str, status: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE artifacts SET last_status = ?, last_verified_at = ? WHERE artifact_id = ?",
                      (status, _now(), artifact_id))

    def revoke_artifact(self, artifact_id: str, reason: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE artifacts SET revoked = 1, revoked_reason = ?, revoked_at = ? "
                "WHERE artifact_id = ? AND revoked = 0", (reason, _now(), artifact_id))
            return cur.rowcount > 0

    # ---- verification runs ---------------------------------------------------------
    def add_run(self, artifact_id: str, context: str, status: str, checks: list[dict[str, Any]],
                duration_ms: float) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO verification_runs (artifact_id, context, overall_status, checks_json, duration_ms, run_at) "
                "VALUES (?,?,?,?,?,?)",
                (artifact_id, context, status, json.dumps(checks), duration_ms, _now()))
            return int(cur.lastrowid)

    def list_runs(self, artifact_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM verification_runs"
        args: tuple = ()
        if artifact_id:
            sql += " WHERE artifact_id = ?"
            args = (artifact_id,)
        sql += " ORDER BY run_id DESC LIMIT ?"
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(sql, (*args, limit))]
        for r in rows:
            r["checks"] = json.loads(r.pop("checks_json"))
        return rows

    # ---- security events -----------------------------------------------------------
    def add_event(self, severity: str, event_type: str, message: str, artifact_id: str | None = None,
                  details: dict[str, Any] | None = None) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO security_events (ts, severity, event_type, artifact_id, message, details_json) "
                "VALUES (?,?,?,?,?,?)",
                (_now(), severity, event_type, artifact_id, message,
                 json.dumps(details, default=str) if details else None))
            return int(cur.lastrowid)

    def list_events(self, limit: int = 500, severity: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM security_events"
        args: tuple = ()
        if severity:
            sql += " WHERE severity = ?"
            args = (severity,)
        sql += " ORDER BY event_id DESC LIMIT ?"
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(sql, (*args, limit))]
        for r in rows:
            r["details"] = json.loads(r.pop("details_json")) if r.get("details_json") else None
        return rows

    # ---- metrics -------------------------------------------------------------------
    def add_metric(self, operation: str, duration_ms: float, artifact_id: str | None = None,
                   size_bytes: int | None = None, extra: dict[str, Any] | None = None) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO metrics (ts, operation, artifact_id, size_bytes, duration_ms, extra_json) "
                "VALUES (?,?,?,?,?,?)",
                (_now(), operation, artifact_id, size_bytes, duration_ms,
                 json.dumps(extra, default=str) if extra else None))

    def list_metrics(self, operation: str | None = None, limit: int = 5000) -> list[dict[str, Any]]:
        sql = "SELECT * FROM metrics"
        args: tuple = ()
        if operation:
            sql += " WHERE operation = ?"
            args = (operation,)
        sql += " ORDER BY metric_id DESC LIMIT ?"
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(sql, (*args, limit))]
        for r in rows:
            r["extra"] = json.loads(r.pop("extra_json")) if r.get("extra_json") else None
        return rows
