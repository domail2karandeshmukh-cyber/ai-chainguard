"""Scenario D - invalid or untrusted signatures.

Bytes and links are intact, but the signature evidence is wrong: corrupted, replayed
from another manifest, produced by an unknown key, produced by a revoked key, or
produced by a trusted key acting outside its role.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

from attacks.common import Variant, edit_envelope, fresh_chain, observe, write_result
from chainguard.crypto.keys import compute_key_id, generate_private_key
from chainguard.manifest.builder import load_envelope_raw, sign_body, write_envelope
from chainguard.manifest.models import ManifestBody

TITLE = "Invalid signature"
DEMONSTRATES = "Only a valid signature from a trusted, unrevoked key in the right role is accepted."


def _resign(cg, artifact_id: str, key, *, key_id: str, role: str | None = None) -> None:
    payload = load_envelope_raw(cg.settings.envelope_path(artifact_id))["payload"]
    payload["signer"]["key_id"] = key_id
    if role:
        payload["signer"]["role"] = role
    write_envelope(sign_body(ManifestBody.model_validate(payload), key), cg.settings.envelope_path(artifact_id))


def run(out_dir: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    variants: list[Variant] = []
    target = "final_model"

    cg, ids = fresh_chain()
    variants.append(observe(cg, "D", "D0", "Control: valid signature", "none", ids[target], "VERIFIED",
                            "final model"))

    # D1 - flip one bit of the signature.
    cg, ids = fresh_chain()

    def flip(raw: dict) -> None:
        sig = bytearray(base64.b64decode(raw["signatures"][0]["sig"]))
        sig[10] ^= 0x01
        raw["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()

    edit_envelope(cg, ids[target], flip)
    variants.append(observe(cg, "D", "D1", "Corrupt one bit of the signature", "bit 0 of byte 10 flipped",
                            ids[target], "FAILED", "final model"))

    # D2 - replay a genuine signature taken from another manifest (same key).
    cg, ids = fresh_chain()
    donor = load_envelope_raw(cg.settings.envelope_path(ids["base_model"]))["signatures"][0]["sig"]
    edit_envelope(cg, ids[target], lambda raw: raw["signatures"][0].update(sig=donor))
    variants.append(observe(cg, "D", "D2", "Replay a signature from another manifest",
                            "valid base-model signature pasted into the final-model envelope",
                            ids[target], "FAILED", "final model"))

    # D3 - attacker signs with their own key (not in the trust store).
    cg, ids = fresh_chain()
    attacker = generate_private_key()
    _resign(cg, ids[target], attacker, key_id=compute_key_id(attacker.public_key()))
    variants.append(observe(cg, "D", "D3", "Sign with an unregistered key",
                            "manifest re-signed by an attacker-generated Ed25519 key", ids[target],
                            "FAILED", "final model"))

    # D4 - the training key is revoked after compromise.
    cg, ids = fresh_chain()
    key_id = cg.repo.active_signer_for_role("training_pipeline")["key_id"]
    cg.trust.revoke_key(key_id, "simulated key compromise")
    variants.append(observe(cg, "D", "D4", "Signature by a revoked key",
                            f"training_pipeline key {key_id} revoked", ids[target], "FAILED", "final model"))

    # D5 - role confusion: the data-steward key (trusted) signs a model.
    cg, ids = fresh_chain()
    steward_key, steward = cg.trust.signing_key("data_steward")
    _resign(cg, ids[target], steward_key, key_id=steward["key_id"], role="training_pipeline")
    variants.append(observe(cg, "D", "D5", "Trusted key used outside its role",
                            "data_steward key signs a model while claiming training_pipeline",
                            ids[target], "FAILED", "final model"))

    # D6 - signature field is not even valid base64.
    cg, ids = fresh_chain()
    edit_envelope(cg, ids[target], lambda raw: raw["signatures"][0].update(sig="not-base64!!"))
    variants.append(observe(cg, "D", "D6", "Malformed signature encoding", "signature replaced by garbage",
                            ids[target], "FAILED", "final model"))

    return write_result("D", TITLE, DEMONSTRATES, variants, started, out_dir)


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2)[:4000])
