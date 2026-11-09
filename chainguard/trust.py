"""Trust store: which public key belongs to which signer identity and role.

Roles separate duties so that one compromised key cannot sign the whole chain:

=====================  ==========================================  ================
Role                   Signs                                       Stage
=====================  ==========================================  ================
data_steward           datasets                                    stage1_dataset
training_pipeline      base and fine-tuned models                  stage2 / stage3
deployment_gateway     deployment records                          stage4
release_manager        the TRUST LOG: key trust, revocations       (root of trust)
model_publisher        EXTERNAL base models (v0.3, Experiment 7)   stage2_external_import
=====================  ==========================================  ================

``model_publisher`` is different from the other roles: its private key belongs to an
OUTSIDE organisation (e.g. a model hub publisher). We never generate or hold it; we
only register the publisher's PUBLIC key after an out-of-band trust decision
(``trust_publisher``). Revoking that key later invalidates every model it signed.

v0.4: the source of truth for trust and revocation is the signed, append-only trust
log (:mod:`chainguard.trustlog`), whose records are signed by the ``release_manager``
root key and pinned in ``keys/trust_root.json``. The SQLite ``signers`` table and the
``revoked`` flags are kept in step as a convenience index for listings, but the
verifier reads the log, so editing the index can no longer add a key or undo a
revocation (closes limitation E5-C4 of v0.3).
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.config import Settings
from chainguard.crypto.keys import (
    compute_key_id,
    env_var_for_role,
    generate_private_key,
    load_private_key_for_role,
    public_key_b64,
    save_private_key,
)
from chainguard.events import CRITICAL, INFO, EventType, log_event
from chainguard.exceptions import KeyMismatchError, KeyNotFoundError, TrustLogError
from chainguard.storage.repository import Repository
from chainguard.trustlog import ROOT_ROLE, TrustLog, TrustState

# Internal roles: key pairs generated and held locally by ``init_keys``.
ROLES: tuple[str, ...] = ("data_steward", "training_pipeline", "release_manager", "deployment_gateway")
# External roles: only public keys are registered (``trust_publisher``).
PUBLISHER_ROLE = "model_publisher"
EXTERNAL_ROLES: tuple[str, ...] = (PUBLISHER_ROLE,)


class TrustStore:
    def __init__(self, settings: Settings, repo: Repository, log: TrustLog | None = None):
        self.settings = settings
        self.repo = repo
        self.log = log or TrustLog(settings)

    def identity_for(self, role: str) -> str:
        return f"{role}@{self.settings.identity_domain}"

    def state(self) -> TrustState:
        """The verified trust state replayed from the signed log."""
        return self.log.load()

    # ------------------------------------------------------------------ key material
    def _key_path(self, role: str):
        return self.settings.keys_dir / f"{role}.pem"

    def _load_or_create(self, role: str) -> tuple[Ed25519PrivateKey, bool]:
        try:
            return load_private_key_for_role(role, self.settings.keys_dir), False
        except KeyNotFoundError:
            key = generate_private_key()
            save_private_key(key, self._key_path(role))
            return key, True

    def _subject(self, key: Ed25519PrivateKey, role: str, identity: str | None = None) -> dict[str, Any]:
        return {"key_id": compute_key_id(key.public_key()), "identity": identity or self.identity_for(role),
                "role": role, "public_key_b64": public_key_b64(key.public_key())}

    def _index_signer(self, subject: dict[str, Any]) -> None:
        if self.repo.get_signer(subject["key_id"]) is None:
            self.repo.add_signer(subject["key_id"], subject["identity"], subject["role"], subject["public_key_b64"])

    # ------------------------------------------------------------------ root of trust
    def _ensure_root(self, rotate: bool = False) -> dict[str, Any]:
        """Make sure the root key exists, the trust log is initialised and (if asked) rotated."""
        if not self.log.exists():
            key, created = self._load_or_create(ROOT_ROLE)
            self.log.initialise(key, self.identity_for(ROOT_ROLE))
            self._index_signer(self._subject(key, ROOT_ROLE))
            self._migrate_index_into_log(key)
            log_event(self.repo, INFO, EventType.TRUST_LOG_INITIALISED,
                      f"Trust log initialised; root key {compute_key_id(key.public_key())} pinned",
                      details={"root_key_id": compute_key_id(key.public_key()), "generated": created})
            return {"role": ROOT_ROLE, "key_id": compute_key_id(key.public_key()),
                    "action": "created" if created else "registered"}
        pin = self.log.pin()
        if rotate:
            old = load_private_key_for_role(ROOT_ROLE, self.settings.keys_dir)
            old_id = compute_key_id(old.public_key())
            if old_id != pin["root_key_id"]:
                raise KeyMismatchError(f"keys/{ROOT_ROLE}.pem ({old_id}) is not the pinned root {pin['root_key_id']}")
            path = self._key_path(ROOT_ROLE)
            if path.exists():
                path.rename(path.with_suffix(f".pem.revoked-{old_id[-8:]}"))
            new = generate_private_key()
            save_private_key(new, path)
            subject = dict(self._subject(new, ROOT_ROLE), replaces=old_id)
            self.log.append("rotate_root", subject, "rotated", signer_key=old)
            self.repo.revoke_signer(old_id, "rotated")
            self._index_signer(subject)
            log_event(self.repo, CRITICAL, EventType.KEY_REVOKED, f"Root key {old_id} rotated to {subject['key_id']}",
                      details={"old": old_id, "new": subject["key_id"]})
            return {"role": ROOT_ROLE, "key_id": subject["key_id"], "action": "created"}
        return {"role": ROOT_ROLE, "key_id": pin["root_key_id"], "action": "existing"}

    def _migrate_index_into_log(self, root_key: Ed25519PrivateKey) -> None:
        """A workspace created before v0.4 has signers and revocations only in SQLite.
        Carry them into the log once so that old chains keep verifying."""
        root_id = compute_key_id(root_key.public_key())
        for s in self.repo.list_signers():
            if s["key_id"] == root_id:
                continue
            subject = {"key_id": s["key_id"], "identity": s["identity"], "role": s["role"],
                       "public_key_b64": s["public_key_b64"]}
            self.log.append("trust_key", subject, "migrated from index", signer_key=root_key)
            if s["revoked_at"]:
                self.log.append("revoke_key", {"key_id": s["key_id"]}, s.get("revoked_reason") or "migrated",
                                signer_key=root_key)
        for a in self.repo.list_artifacts():
            if a["revoked"]:
                self.log.append("revoke_artifact", {"artifact_id": a["artifact_id"]},
                                a.get("revoked_reason") or "migrated", signer_key=root_key)

    # ------------------------------------------------------------------ public API
    def init_keys(self, roles: tuple[str, ...] = ROLES, rotate: bool = False) -> list[dict[str, Any]]:
        """Make sure every role has a usable key pair trusted in the signed log.

        * key file exists and is trusted     -> nothing to do
        * key file/env exists, not trusted   -> append a trust_key record for it
        * no key at all                      -> generate, save (0600), trust
        * ``rotate=True``                    -> revoke the current key, generate a new one
          (for the root key: a rotate_root record signed by the old root)
        """
        out = [self._ensure_root(rotate=rotate and ROOT_ROLE in roles)]
        state = self.state()
        if not state.ok:
            raise TrustLogError(f"trust log unusable: {state.error}")
        for role in roles:
            if role == ROOT_ROLE:
                continue
            current = next(iter(state.active_signers_for_role(role)), None)
            if rotate and current:
                self.revoke_key(current["key_id"], "rotated")
                path = self._key_path(role)
                if path.exists():
                    path.rename(path.with_suffix(f".pem.revoked-{current['key_id'][-8:]}"))
                current = None
            key, created = self._load_or_create(role)
            key_id = compute_key_id(key.public_key())
            if current and current["key_id"] == key_id:
                out.append({"role": role, "key_id": key_id, "action": "existing"})
                continue
            known = state.signer(key_id)
            if known and known["revoked_at"]:
                raise KeyMismatchError(f"keys/{role}.pem is the REVOKED key {key_id}; remove it and run keys init")
            if known is None:
                subject = self._subject(key, role)
                self.log.append("trust_key", subject)
                log_event(self.repo, INFO, EventType.KEY_CREATED, f"Registered {role} key {key_id}",
                          details={"role": role, "key_id": key_id, "generated": created})
            self._index_signer(self._subject(key, role))
            out.append({"role": role, "key_id": key_id, "action": "created" if created else "registered"})
        return out

    def register_public_key(self, role: str, public_key_b64_value: str, identity: str | None = None) -> str:
        """Trust an external public key (e.g. a third-party model publisher).

        Idempotent for the same (key, role, identity). Refuses to re-register a known key
        under a different role or identity, which would silently widen what it may sign.
        """
        from chainguard.crypto.keys import public_key_from_b64

        key_id = compute_key_id(public_key_from_b64(public_key_b64_value))
        identity = identity or self.identity_for(role)
        state = self.state()
        if not state.ok:
            raise TrustLogError(f"trust log unusable: {state.error}")
        existing = state.signer(key_id) or self.repo.get_signer(key_id)
        if existing is not None:
            if existing["role"] != role or existing["identity"] != identity:
                raise KeyMismatchError(f"Key {key_id} is already trusted as {existing['identity']} "
                                       f"({existing['role']}); refusing to re-register it")
            if state.signer(key_id) is None:   # index knows it, log does not: trust it properly
                self.log.append("trust_key", {"key_id": key_id, "identity": identity, "role": role,
                                              "public_key_b64": public_key_b64_value})
            return key_id
        subject = {"key_id": key_id, "identity": identity, "role": role, "public_key_b64": public_key_b64_value}
        self.log.append("trust_key", subject)
        self._index_signer(subject)
        log_event(self.repo, INFO, EventType.KEY_CREATED, f"Trusted external {role} key {key_id} ({identity})",
                  details={"role": role, "key_id": key_id, "identity": identity, "external": True})
        return key_id

    def trust_publisher(self, public_key_b64_value: str, identity: str) -> str:
        """Register an outside model publisher's PUBLIC key with role model_publisher."""
        if "@" not in identity:
            raise KeyMismatchError("publisher identity must look like name@organisation")
        return self.register_public_key(PUBLISHER_ROLE, public_key_b64_value, identity)

    def signing_key(self, role: str) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
        """Load the private key for ``role`` and check it is the key the signed log trusts.

        A mismatch means a stale or substituted key file; signing with it would produce
        signatures that nobody can verify, so we refuse early.
        """
        state = self.state()
        if not state.ok:
            raise TrustLogError(f"cannot sign: trust log unusable ({state.error})")
        active = state.active_signers_for_role(role)
        if not active:
            raise KeyNotFoundError(f"No active trusted key for role '{role}'. Run: keys init")
        key = load_private_key_for_role(role, self.settings.keys_dir)
        key_id = compute_key_id(key.public_key())
        signer = next((s for s in active if s["key_id"] == key_id), None)
        if signer is None:
            raise KeyMismatchError(
                f"Private key for '{role}' ({key_id}) is not the trusted key {active[-1]['key_id']}"
                f" (check keys/{role}.pem or ${env_var_for_role(role)})")
        return key, signer

    def revoke_key(self, key_id: str, reason: str) -> bool:
        state = self.state()
        if not state.ok:
            raise TrustLogError(f"cannot revoke: trust log unusable ({state.error})")
        known = state.signer(key_id)
        if known is None or known["revoked_at"]:
            self.repo.revoke_signer(key_id, reason)   # keep the index honest even if the log has nothing to do
            return False
        self.log.append("revoke_key", {"key_id": key_id}, reason)
        self.repo.revoke_signer(key_id, reason)
        log_event(self.repo, CRITICAL, EventType.KEY_REVOKED, f"Key {key_id} revoked: {reason}",
                  details={"key_id": key_id, "reason": reason, "trust_log_seq": self.log.pin()["head_seq"]})
        return True

    def revoke_artifact(self, artifact_id: str, reason: str) -> bool:
        """Append a signed revocation record and mirror it into the index. Final: no un-revoke."""
        state = self.state()
        if not state.ok:
            raise TrustLogError(f"cannot revoke: trust log unusable ({state.error})")
        if state.artifact_revocation(artifact_id) is not None:
            self.repo.revoke_artifact(artifact_id, reason)
            return False
        self.log.append("revoke_artifact", {"artifact_id": artifact_id}, reason)
        self.repo.revoke_artifact(artifact_id, reason)
        return True
