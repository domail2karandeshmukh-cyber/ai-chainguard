"""Signed, append-only trust log: the root of trust for signers and revocations (v0.4).

The problem it closes (Experiment 5, variant E5-C4 of v0.3)
-----------------------------------------------------------
Until v0.3 the trust store (which key may sign which role) and the revocation flags
lived in the SQLite index. The verifier recomputed every hash and signature from the
signed envelopes, but for *who is trusted* and *what is revoked* it had to believe
the index. Anyone able to write that one file could therefore un-revoke a withdrawn
model, or insert a key of their own, and nothing would notice.

Design
------
* The log is a file of records, one per line (JSON Lines)::

      {"entry": {"seq": n, "prev": "sha256:...", "ts": ..., "action": ..., "subject": {...}},
       "key_id": "<root key id>", "sig": "<base64 Ed25519 signature over canonical_json(entry)>"}

  ``prev`` is the SHA-256 of the previous record (a hash chain, as in Git or a
  transparency log) and ``seq`` counts from 1, so no record can be removed, inserted
  or reordered without breaking the chain.
* Every record is signed by the **root key**, the key of the ``release_manager``
  role. Actions: ``trust_key`` (a key becomes trusted for a role), ``revoke_key``,
  ``revoke_artifact`` and ``rotate_root`` (a new root key, signed by the old one).
  There is no un-revoke action: the log is append-only and a revocation is final.
* The **pin** ``keys/trust_root.json`` lives in the trusted keys directory (0600). It
  holds the current root public key and the sequence number and hash of the last
  record. A log that does not end exactly at the pinned head is rejected, so
  truncation (rolling back to before a revocation) and wholesale substitution are
  detected, not only forgery.
* The verifier derives the trust state (trusted keys, revoked keys, revoked
  artifacts) from the log **only**. The SQLite tables remain a convenience index for
  listings; any disagreement between index and log is reported as index tampering.

Trust assumptions (unchanged from the threat model): the keys directory, the policy
and the verifier are trusted; artifact storage, the index and the network are not.
The log can live in hostile storage and can be copied to another verifier together
with the small pin file.

Relation to existing systems: a single-writer transparency log (RFC 6962 without a
Merkle tree, because the log is tiny) with TUF-style root-key pinning and rollback
protection. A production deployment would additionally publish the records to a
shared log such as Sigstore Rekor so that every verifier sees the same history.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.config import Settings
from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.hashing import sha256_bytes
from chainguard.crypto.keys import (
    compute_key_id,
    load_private_key_for_role,
    public_key_b64,
    public_key_from_b64,
)
from chainguard.crypto.signing import sign_bytes, verify_bytes
from chainguard.exceptions import KeyMismatchError, TrustLogError
from chainguard.manifest.builder import utc_now_iso
from chainguard.metrics import timed

ROOT_ROLE = "release_manager"
GENESIS_PREV = "sha256:" + "0" * 64
ACTIONS = ("trust_key", "revoke_key", "revoke_artifact", "rotate_root")


def record_hash(record: dict[str, Any]) -> str:
    return "sha256:" + sha256_bytes(canonical_json(record))


@dataclass
class TrustState:
    """What the verifier may believe about keys and revocations. ``ok`` is False when
    the log is missing, truncated, tampered with or not pinned; every consumer then
    fails closed."""

    ok: bool
    error: str | None = None
    root_key_id: str | None = None
    head_seq: int = 0
    head_hash: str | None = None
    signers: dict[str, dict[str, Any]] = field(default_factory=dict)
    revoked_artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    entries: list[dict[str, Any]] = field(default_factory=list)
    verify_ms: float = 0.0

    def signer(self, key_id: str) -> dict[str, Any] | None:
        return self.signers.get(key_id)

    def active_signers_for_role(self, role: str) -> list[dict[str, Any]]:
        return [s for s in self.signers.values() if s["role"] == role and not s["revoked_at"]]

    def artifact_revocation(self, artifact_id: str) -> dict[str, Any] | None:
        return self.revoked_artifacts.get(artifact_id)

    def summary(self) -> dict[str, Any]:
        return {"ok": self.ok, "error": self.error, "root_key_id": self.root_key_id,
                "head_seq": self.head_seq, "head_hash": self.head_hash,
                "trusted_keys": sum(1 for s in self.signers.values() if not s["revoked_at"]),
                "revoked_keys": sum(1 for s in self.signers.values() if s["revoked_at"]),
                "revoked_artifacts": len(self.revoked_artifacts), "verify_ms": self.verify_ms}


class TrustLog:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._sig_cache: dict[tuple[str, str], bool] = {}   # (record hash, key id) -> signature valid

    # ------------------------------------------------------------------ paths and pin
    @property
    def log_path(self):
        return self.settings.trust_log_path

    @property
    def pin_path(self):
        return self.settings.trust_root_path

    def exists(self) -> bool:
        return self.pin_path.exists()

    def pin(self) -> dict[str, Any] | None:
        if not self.pin_path.exists():
            return None
        try:
            data = json.loads(self.pin_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TrustLogError(f"trust root pin unreadable: {exc}") from exc
        for k in ("root_key_id", "root_public_key_b64", "head_seq", "head_hash"):
            if k not in data:
                raise TrustLogError(f"trust root pin is missing '{k}'")
        return data

    def _write_pin(self, data: dict[str, Any]) -> None:
        self.pin_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.pin_path.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.pin_path)

    # ------------------------------------------------------------------ writing
    def root_private_key(self) -> Ed25519PrivateKey:
        return load_private_key_for_role(ROOT_ROLE, self.settings.keys_dir)

    def initialise(self, root_key: Ed25519PrivateKey, identity: str) -> dict[str, Any]:
        """Create the pin and the genesis record (the root key trusting itself)."""
        if self.exists():
            raise TrustLogError(f"trust log already initialised ({self.pin_path})")
        key_id = compute_key_id(root_key.public_key())
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.exists():
            self.log_path.unlink()   # a log without a pin is worthless; start clean
        self._write_pin({"root_key_id": key_id, "root_public_key_b64": public_key_b64(root_key.public_key()),
                         "head_seq": 0, "head_hash": GENESIS_PREV, "created_at": utc_now_iso()})
        return self.append("trust_key", {"key_id": key_id, "identity": identity, "role": ROOT_ROLE,
                                         "public_key_b64": public_key_b64(root_key.public_key())},
                           signer_key=root_key)

    def append(self, action: str, subject: dict[str, Any], reason: str | None = None, *,
               signer_key: Ed25519PrivateKey | None = None) -> dict[str, Any]:
        """Append one record signed by the current root key and advance the pin."""
        if action not in ACTIONS:
            raise TrustLogError(f"unknown trust log action {action!r}")
        pin = self.pin()
        if pin is None:
            raise TrustLogError("trust log not initialised: run `keys init`")
        key = signer_key or self.root_private_key()
        key_id = compute_key_id(key.public_key())
        if key_id != pin["root_key_id"]:
            raise KeyMismatchError(f"trust log records must be signed by the root key {pin['root_key_id']}, "
                                   f"not {key_id} (check keys/{ROOT_ROLE}.pem)")
        entry: dict[str, Any] = {"seq": int(pin["head_seq"]) + 1, "prev": pin["head_hash"], "ts": utc_now_iso(),
                                 "action": action, "subject": subject}
        if reason:
            entry["reason"] = reason
        record = {"entry": entry, "key_id": key_id, "sig": sign_bytes(key, canonical_json(entry))}
        line = canonical_json(record)
        with self.log_path.open("ab") as fh:
            fh.write(line + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        new_pin = dict(pin, head_seq=entry["seq"], head_hash=record_hash(record), updated_at=entry["ts"])
        if action == "rotate_root":
            new_pin["root_key_id"] = subject["key_id"]
            new_pin["root_public_key_b64"] = subject["public_key_b64"]
        self._write_pin(new_pin)
        return record

    # ------------------------------------------------------------------ reading
    def load(self) -> TrustState:
        """Replay the log against the pin. Never raises: an unusable log is a result."""
        with timed() as t:
            state = self._load()
        state.verify_ms = round(t.ms, 3)
        return state

    def _load(self) -> TrustState:
        try:
            pin = self.pin()
        except TrustLogError as exc:
            return TrustState(ok=False, error=str(exc))
        if pin is None:
            return TrustState(ok=False, error="no trust root pinned (keys/trust_root.json missing): run `keys init`")
        if not self.log_path.exists():
            return TrustState(ok=False, error=f"trust log missing ({self.log_path.name}); pinned head is #{pin['head_seq']}",
                              root_key_id=pin["root_key_id"])

        state = TrustState(ok=True, root_key_id=pin["root_key_id"])
        active_key_id: str | None = None
        active_pub: str | None = None
        prev = GENESIS_PREV
        try:
            with self.log_path.open("rb") as fh:
                lines = [ln for ln in fh.read().split(b"\n") if ln.strip()]
        except OSError as exc:
            return TrustState(ok=False, error=f"trust log unreadable: {exc}", root_key_id=pin["root_key_id"])

        for i, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
                entry = record["entry"]
                seq, rec_prev, action, subject = entry["seq"], entry["prev"], entry["action"], entry["subject"]
                sig, key_id = record["sig"], record["key_id"]
            except (ValueError, KeyError, TypeError) as exc:
                return self._bad(state, f"record {i} malformed: {exc}")
            if seq != i:
                return self._bad(state, f"record {i} carries seq {seq}: records inserted or removed")
            if rec_prev != prev:
                return self._bad(state, f"record {i}: hash chain broken (prev does not match record {i - 1})")
            if action not in ACTIONS:
                return self._bad(state, f"record {i}: unknown action {action!r}")

            # --- which key must have signed this record -------------------------------
            if i == 1:
                if action != "trust_key" or subject.get("role") != ROOT_ROLE or subject.get("key_id") != key_id:
                    return self._bad(state, "record 1 must be the root key trusting itself")
                pub = subject.get("public_key_b64", "")
                try:
                    if compute_key_id(public_key_from_b64(pub)) != key_id:
                        return self._bad(state, "record 1: root key id does not match its public key")
                except ValueError:
                    return self._bad(state, "record 1: root public key malformed")
                active_key_id, active_pub = key_id, pub
            elif key_id != active_key_id:
                return self._bad(state, f"record {i} signed by {key_id}, expected root {active_key_id}")

            h = record_hash(record)
            cache_key = (h, key_id)
            valid = self._sig_cache.get(cache_key)
            if valid is None:
                valid = verify_bytes(active_pub or "", canonical_json(entry), sig)
                if valid:
                    self._sig_cache[cache_key] = True
            if not valid:
                return self._bad(state, f"record {i} ({action}): signature by root key invalid - log tampered with")

            # --- apply ---------------------------------------------------------------------
            problem = self._apply(state, i, entry, action, subject)
            if problem:
                return self._bad(state, problem)
            if action == "rotate_root":
                active_key_id, active_pub = subject["key_id"], subject["public_key_b64"]
            state.entries.append({"seq": seq, "ts": entry.get("ts"), "action": action, "subject": subject,
                                  "reason": entry.get("reason"), "hash": h, "key_id": key_id})
            prev = h
            state.head_seq, state.head_hash = seq, h

        if state.head_seq != int(pin["head_seq"]) or state.head_hash != pin["head_hash"]:
            kind = "truncated (rollback)" if state.head_seq < int(pin["head_seq"]) else "does not match the pinned head"
            return self._bad(state, f"trust log {kind}: log ends at #{state.head_seq}, pin says #{pin['head_seq']}")
        if active_key_id != pin["root_key_id"]:
            return self._bad(state, f"log root {active_key_id} is not the pinned root {pin['root_key_id']}")
        return state

    @staticmethod
    def _bad(state: TrustState, error: str) -> TrustState:
        return TrustState(ok=False, error=error, root_key_id=state.root_key_id, head_seq=state.head_seq,
                          head_hash=state.head_hash)

    @staticmethod
    def _apply(state: TrustState, i: int, entry: dict[str, Any], action: str, subject: dict[str, Any]) -> str | None:
        ts = entry.get("ts")
        if action in ("trust_key", "rotate_root"):
            for k in ("key_id", "identity", "role", "public_key_b64"):
                if not subject.get(k):
                    return f"record {i} ({action}): subject lacks '{k}'"
            try:
                if compute_key_id(public_key_from_b64(subject["public_key_b64"])) != subject["key_id"]:
                    return f"record {i} ({action}): key id does not match the public key"
            except ValueError:
                return f"record {i} ({action}): public key malformed"
            existing = state.signers.get(subject["key_id"])
            if existing is not None:
                if existing["role"] != subject["role"] or existing["identity"] != subject["identity"]:
                    return f"record {i}: key {subject['key_id']} re-trusted with a different role or identity"
                return None   # idempotent re-trust
            state.signers[subject["key_id"]] = {
                "key_id": subject["key_id"], "identity": subject["identity"], "role": subject["role"],
                "public_key_b64": subject["public_key_b64"], "trusted_at": ts, "seq": i,
                "revoked_at": None, "revoked_reason": None, "revoked_seq": None,
            }
            if action == "rotate_root":
                if subject["role"] != ROOT_ROLE:
                    return f"record {i}: rotate_root subject must have role {ROOT_ROLE}"
                old = state.signers.get(subject.get("replaces") or "")
                if old is None:
                    old = next((s for s in state.signers.values()
                                if s["role"] == ROOT_ROLE and not s["revoked_at"] and s["key_id"] != subject["key_id"]),
                               None)
                if old is not None:
                    old.update(revoked_at=ts, revoked_reason="rotated", revoked_seq=i)
            return None
        if action == "revoke_key":
            s = state.signers.get(subject.get("key_id", ""))
            if s is None:
                return f"record {i}: revocation of unknown key {subject.get('key_id')}"
            if not s["revoked_at"]:
                s.update(revoked_at=ts, revoked_reason=entry.get("reason"), revoked_seq=i)
            return None
        if action == "revoke_artifact":
            aid = subject.get("artifact_id")
            if not aid:
                return f"record {i}: revoke_artifact without artifact_id"
            state.revoked_artifacts.setdefault(aid, {"artifact_id": aid, "reason": entry.get("reason"),
                                                     "revoked_at": ts, "seq": i})
            return None
        return None
