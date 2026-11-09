"""Trust store: which public key belongs to which signer identity and role.

Roles separate duties so that one compromised key cannot sign the whole chain:

=====================  ==========================================  ================
Role                   Signs                                       Stage
=====================  ==========================================  ================
data_steward           datasets                                    stage1_dataset
training_pipeline      base and fine-tuned models                  stage2 / stage3
deployment_gateway     deployment records                          stage4
release_manager        reserved: manual approvals, revocations     (none in policy)
model_publisher        EXTERNAL base models (v0.3, Experiment 7)   stage2_external_import
=====================  ==========================================  ================

``model_publisher`` is different from the other roles: its private key belongs to an
OUTSIDE organisation (e.g. a model hub publisher). We never generate or hold it; we
only register the publisher's PUBLIC key after an out-of-band trust decision
(``trust_publisher``). Revoking that key later invalidates every model it signed.

PROTOTYPE NOTE: the trust store lives in the SQLite index. Anyone who can write the
DB could add a key. Production would distribute the trust store as a signed, pinned
file (or use Sigstore's Fulcio root + identity policies).
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
from chainguard.exceptions import KeyMismatchError, KeyNotFoundError
from chainguard.storage.repository import Repository

# Internal roles: key pairs generated and held locally by ``init_keys``.
ROLES: tuple[str, ...] = ("data_steward", "training_pipeline", "release_manager", "deployment_gateway")
# External roles: only public keys are registered (``trust_publisher``).
PUBLISHER_ROLE = "model_publisher"
EXTERNAL_ROLES: tuple[str, ...] = (PUBLISHER_ROLE,)


class TrustStore:
    def __init__(self, settings: Settings, repo: Repository):
        self.settings = settings
        self.repo = repo

    def identity_for(self, role: str) -> str:
        return f"{role}@{self.settings.identity_domain}"

    def init_keys(self, roles: tuple[str, ...] = ROLES, rotate: bool = False) -> list[dict[str, Any]]:
        """Make sure every role has a usable key pair registered in the trust store.

        * key file exists and is registered  -> nothing to do
        * key file/env exists, not registered -> register its public key
        * no key at all                       -> generate, save (0600), register
        * ``rotate=True``                     -> revoke the current key, generate a new one
        """
        out = []
        for role in roles:
            path = self.settings.keys_dir / f"{role}.pem"
            current = self.repo.active_signer_for_role(role)
            if rotate and current:
                self.revoke_key(current["key_id"], "rotated")
                if path.exists():
                    path.rename(path.with_suffix(f".pem.revoked-{current['key_id'][-8:]}"))
                current = None

            try:
                key = load_private_key_for_role(role, self.settings.keys_dir)
                created = False
            except KeyNotFoundError:
                key = generate_private_key()
                save_private_key(key, path)
                created = True

            key_id = compute_key_id(key.public_key())
            if current and current["key_id"] == key_id:
                out.append({"role": role, "key_id": key_id, "action": "existing"})
                continue
            if self.repo.get_signer(key_id) is None:
                self.repo.add_signer(key_id, self.identity_for(role), role, public_key_b64(key.public_key()))
                log_event(self.repo, INFO, EventType.KEY_CREATED, f"Registered {role} key {key_id}",
                          details={"role": role, "key_id": key_id, "generated": created})
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
        existing = self.repo.get_signer(key_id)
        if existing is not None:
            if existing["role"] != role or existing["identity"] != identity:
                raise KeyMismatchError(f"Key {key_id} is already trusted as {existing['identity']} "
                                       f"({existing['role']}); refusing to re-register it")
            return key_id
        self.repo.add_signer(key_id, identity, role, public_key_b64_value)
        log_event(self.repo, INFO, EventType.KEY_CREATED, f"Trusted external {role} key {key_id} ({identity})",
                  details={"role": role, "key_id": key_id, "identity": identity, "external": True})
        return key_id

    def trust_publisher(self, public_key_b64_value: str, identity: str) -> str:
        """Register an outside model publisher's PUBLIC key with role model_publisher."""
        if "@" not in identity:
            raise KeyMismatchError("publisher identity must look like name@organisation")
        return self.register_public_key(PUBLISHER_ROLE, public_key_b64_value, identity)

    def signing_key(self, role: str) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
        """Load the private key for ``role`` and check it matches the trusted public key.

        A mismatch means a stale or substituted key file; signing with it would produce
        signatures that nobody can verify, so we refuse early.
        """
        signer = self.repo.active_signer_for_role(role)
        if signer is None:
            raise KeyNotFoundError(f"No active trusted key for role '{role}'. Run: keys init")
        key = load_private_key_for_role(role, self.settings.keys_dir)
        key_id = compute_key_id(key.public_key())
        if key_id != signer["key_id"]:
            raise KeyMismatchError(
                f"Private key for '{role}' ({key_id}) does not match the trusted key {signer['key_id']}"
                f" (check keys/{role}.pem or ${env_var_for_role(role)})")
        return key, signer

    def revoke_key(self, key_id: str, reason: str) -> bool:
        ok = self.repo.revoke_signer(key_id, reason)
        if ok:
            log_event(self.repo, CRITICAL, EventType.KEY_REVOKED, f"Key {key_id} revoked: {reason}",
                      details={"key_id": key_id, "reason": reason})
        return ok
