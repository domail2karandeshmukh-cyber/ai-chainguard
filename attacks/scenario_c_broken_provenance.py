"""Scenario C - broken provenance.

The attacker does not touch model bytes; instead they attack the LINKS between
artifacts: deleting the parent record, rewriting history under a re-signed parent,
editing the parent list, or pushing a model that has no dataset ancestry at all.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from attacks.common import Variant, edit_envelope, fresh_chain, observe, subject_path, write_result
from chainguard.crypto.hashing import sha256_file
from chainguard.manifest.builder import compute_manifest_digest, load_envelope_raw, sign_body, write_envelope
from chainguard.manifest.models import ManifestBody, MerkleInfo
from chainguard.provenance.merkle import file_line_leaf_hashes, merkle_root_from_leaf_hashes, root_hex

TITLE = "Broken provenance"
DEMONSTRATES = "Hash-linked parents make it impossible to cut, swap or rewrite ancestry unnoticed."


def run(out_dir: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    variants: list[Variant] = []

    cg, ids = fresh_chain()
    variants.append(observe(cg, "C", "C0", "Control: intact chain", "none", ids["base_model"], "VERIFIED",
                            "base model"))

    # C1 - delete the parent dataset record (envelope + index row).
    cg, ids = fresh_chain()
    cg.settings.envelope_path(ids["train_dataset"]).unlink()
    cg.repo.delete_artifact(ids["train_dataset"])
    variants.append(observe(cg, "C", "C1", "Delete the parent dataset record",
                            "envelope and index row of the training dataset removed", ids["base_model"],
                            "FAILED", "base model"))

    # C2 - rewrite history: a malicious insider WITH the data-steward key replaces the
    # dataset content and re-signs a valid manifest under the same artifact id.
    cg, ids = fresh_chain()
    ds = ids["train_dataset"]
    p = subject_path(cg, ds)
    lines = p.read_text().splitlines()
    for i in range(1, 60):
        head, _, label = lines[i].rpartition(",")
        lines[i] = f"{head},7"
    p.write_text("\n".join(lines) + "\n")
    payload = load_envelope_raw(cg.settings.envelope_path(ds))["payload"]
    payload["subject"]["sha256"] = sha256_file(p)
    payload["subject"]["size_bytes"] = p.stat().st_size
    leaves = file_line_leaf_hashes(p)
    payload["subject"]["merkle"] = MerkleInfo(root=root_hex(merkle_root_from_leaf_hashes(leaves)),
                                              leaf_count=len(leaves)).model_dump()
    key, _ = cg.trust.signing_key("data_steward")
    write_envelope(sign_body(ManifestBody.model_validate(payload), key), cg.settings.envelope_path(ds))
    cg.settings.leaves_path(ds).unlink(missing_ok=True)
    dataset_view = cg.verifier.verify(ds, context="attack:C").status.value
    variants.append(observe(cg, "C", "C2", "Re-sign a modified parent (history rewrite)",
                            "dataset changed and re-signed with the legitimate data-steward key",
                            ids["base_model"], "FAILED", "base model",
                            rewritten_dataset_alone=dataset_view,
                            note="the re-signed dataset verifies on its own; the hash link from the "
                                 "model exposes the rewrite"))

    # C3 - point the model at a different (legitimate) dataset without re-signing.
    cg, ids = fresh_chain()
    other = ids["finetune_dataset"]
    other_digest = compute_manifest_digest(load_envelope_raw(cg.settings.envelope_path(other))["payload"])

    def repoint(raw: dict) -> None:
        raw["payload"]["parents"][0]["artifact_id"] = other
        raw["payload"]["parents"][0]["manifest_digest"] = other_digest

    edit_envelope(cg, ids["base_model"], repoint)
    variants.append(observe(cg, "C", "C3", "Edit parent link without re-signing",
                            "base model now claims the fine-tune dataset as parent", ids["base_model"],
                            "FAILED", "base model"))

    # C4 - rogue pipeline: legitimate training key signs a model with NO dataset parent.
    cg, ids = fresh_chain()
    src = subject_path(cg, ids["base_model"])
    rogue = cg.settings.models_dir / "orphan-model.safetensors"
    rogue.write_bytes(src.read_bytes())
    reg = cg.registry.register(rogue, name="orphan-model", artifact_type="base_model", stage="stage2_training",
                               role="training_pipeline", parents=[], enforce_policy=False)
    variants.append(observe(cg, "C", "C4", "Model with no dataset ancestry",
                            "validly signed by training_pipeline, registration policy bypassed",
                            reg.artifact_id, "FAILED", "orphan model"))

    return write_result("C", TITLE, DEMONSTRATES, variants, started, out_dir)


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2)[:4000])
