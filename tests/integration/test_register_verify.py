"""Registry + verifier integration tests: success and every important failure condition."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from chainguard.crypto.keys import compute_key_id, generate_private_key
from chainguard.exceptions import ConfigError, PolicyViolationError, RegistrationError
from chainguard.manifest.builder import load_envelope_raw, sign_body, write_envelope
from chainguard.manifest.models import ManifestBody
from chainguard.verification.results import Status
from chainguard.verification.verified_io import open_verified


def failed(report):
    return set(report.failed_checks())


def edit(cg, artifact_id, fn):
    p = cg.settings.envelope_path(artifact_id)
    raw = load_envelope_raw(p)
    fn(raw)
    write_envelope(raw, p)


# ---------------------------------------------------------------- success
def test_clean_chain_verifies(cg, chain):
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.VERIFIED
    assert {a.artifact_id for a in r.ancestors} == {chain["base"], chain["dataset"]}
    assert cg.repo.get_artifact(chain["final"])["last_status"] == "VERIFIED"


def test_registration_records_events_and_metrics(cg, chain):
    types = {e["event_type"] for e in cg.repo.list_events()}
    assert "ARTIFACT_REGISTERED" in types
    ops = {m["operation"] for m in cg.repo.list_metrics()}
    assert {"hash", "merkle", "sign", "register_total"} <= ops


def test_dataset_has_merkle_root_and_sidecar(cg, chain):
    row = cg.repo.get_artifact(chain["dataset"])
    assert row["merkle_root"].startswith("sha256:")
    assert cg.settings.leaves_path(chain["dataset"]).exists()


# ---------------------------------------------------------------- modified artifacts
def test_modified_dataset_detected_and_localised(cg, chain):
    p = Path(chain["dataset_file"])
    lines = p.read_text().splitlines()
    head, _, label = lines[7].rpartition(",")
    lines[7] = f"{head},{(int(label) + 1) % 10}"
    p.write_text("\n".join(lines) + "\n")
    r = cg.verifier.verify(chain["dataset"])
    assert r.status == Status.FAILED and {"V1", "V2"} <= failed(r)
    assert r.check("V2").details["diff"]["changed_lines"] == [7]
    # Every descendant fails through the ancestry check.
    assert "V6" in failed(cg.verifier.verify(chain["final"]))


def test_modified_model_detected(cg, chain):
    Path(chain["base_file"]).write_bytes(b"evil weights")
    r = cg.verifier.verify(chain["base"])
    assert r.status == Status.FAILED and "V1" in failed(r)


def test_missing_artifact_file(cg, chain):
    Path(chain["base_file"]).unlink()
    assert "V1" in failed(cg.verifier.verify(chain["base"]))


def test_candidate_file_override(cg, chain, tmp_path):
    good = tmp_path / "copy.bin"
    shutil.copyfile(chain["final_file"], good)
    assert cg.verifier.verify(chain["final"], file_path=good).status == Status.VERIFIED
    good.write_bytes(b"other")
    assert "V1" in failed(cg.verifier.verify(chain["final"], file_path=good))


# ---------------------------------------------------------------- signatures
def test_wrong_signature(cg, chain):
    edit(cg, chain["final"], lambda raw: raw["signatures"][0].update(
        sig=load_envelope_raw(cg.settings.envelope_path(chain["base"]))["signatures"][0]["sig"]))
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and "V3" in failed(r)


def test_payload_edit_without_resigning(cg, chain):
    edit(cg, chain["final"], lambda raw: raw["payload"].update(version="9.9.9"))
    assert "V3" in failed(cg.verifier.verify(chain["final"]))


def test_unknown_signing_key(cg, chain):
    k = generate_private_key()
    raw = load_envelope_raw(cg.settings.envelope_path(chain["final"]))
    raw["payload"]["signer"]["key_id"] = compute_key_id(k.public_key())
    write_envelope(sign_body(ManifestBody.model_validate(raw["payload"]), k), cg.settings.envelope_path(chain["final"]))
    assert {"V3", "V4"} <= failed(cg.verifier.verify(chain["final"]))


def test_role_mismatch(cg, chain):
    key, steward = cg.trust.signing_key("data_steward")
    raw = load_envelope_raw(cg.settings.envelope_path(chain["final"]))
    raw["payload"]["signer"].update(key_id=steward["key_id"])  # claims training_pipeline role
    write_envelope(sign_body(ManifestBody.model_validate(raw["payload"]), key), cg.settings.envelope_path(chain["final"]))
    r = cg.verifier.verify(chain["final"])
    assert "V4" in failed(r) and "V3" not in failed(r)


def test_revoked_signing_key(cg, chain):
    kid = cg.repo.active_signer_for_role("training_pipeline")["key_id"]
    cg.trust.revoke_key(kid, "compromised")
    assert "V4" in failed(cg.verifier.verify(chain["base"]))


# ---------------------------------------------------------------- provenance
def test_broken_provenance_missing_parent(cg, chain):
    cg.settings.envelope_path(chain["dataset"]).unlink()
    r = cg.verifier.verify(chain["base"])
    assert r.status == Status.FAILED and "V5" in failed(r)


def test_parent_rewritten_and_resigned(cg, chain):
    """A valid re-signature of the parent still breaks the child's hash link."""
    p = Path(chain["dataset_file"])
    p.write_text(p.read_text() + p.read_text().splitlines()[1] + "\n")
    from chainguard.crypto.hashing import sha256_file
    from chainguard.manifest.models import MerkleInfo
    from chainguard.provenance.merkle import file_line_leaf_hashes, merkle_root_from_leaf_hashes, root_hex

    raw = load_envelope_raw(cg.settings.envelope_path(chain["dataset"]))
    lv = file_line_leaf_hashes(p)
    raw["payload"]["subject"].update(sha256=sha256_file(p), size_bytes=p.stat().st_size,
                                     merkle=MerkleInfo(root=root_hex(merkle_root_from_leaf_hashes(lv)),
                                                       leaf_count=len(lv)).model_dump())
    key, _ = cg.trust.signing_key("data_steward")
    write_envelope(sign_body(ManifestBody.model_validate(raw["payload"]), key),
                   cg.settings.envelope_path(chain["dataset"]))
    assert cg.verifier.verify(chain["dataset"]).status == Status.VERIFIED
    assert "V5" in failed(cg.verifier.verify(chain["base"]))


def test_envelope_swap_detected(cg, chain):
    shutil.copyfile(cg.settings.envelope_path(chain["base"]), cg.settings.envelope_path(chain["final"]))
    assert "V0" in failed(cg.verifier.verify(chain["final"]))


def test_malformed_envelope(cg, chain):
    cg.settings.envelope_path(chain["final"]).write_text("{not json")
    assert "V0" in failed(cg.verifier.verify(chain["final"]))


def test_unknown_artifact(cg):
    r = cg.verifier.verify("does-not-exist")
    assert r.status == Status.FAILED and failed(r) == {"V0"}


def test_extra_field_in_payload(cg, chain):
    edit(cg, chain["final"], lambda raw: raw["payload"].update(safe=True))
    assert "V0" in failed(cg.verifier.verify(chain["final"]))


def test_index_row_deleted_cannot_escape_revocation(cg, chain):
    cg.repo.delete_artifact(chain["final"])
    assert "V7" in failed(cg.verifier.verify(chain["final"]))


def test_policy_violation_detected_by_verifier(cg, dataset_csv):
    f = cg.settings.models_dir / "orphan.bin"
    f.write_bytes(b"w" * 100)
    reg = cg.registry.register(f, name="orphan", artifact_type="base_model", stage="stage2_training",
                               role="training_pipeline", enforce_policy=False)
    assert "V8" in failed(cg.verifier.verify(reg.artifact_id))


# ---------------------------------------------------------------- revocation
def test_revoked_artifact(cg, chain):
    cg.registry.revoke(chain["final"], "test")
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and "V7" in failed(r) and r.revoked


def test_revoked_ancestor_propagates(cg, chain):
    cg.registry.revoke(chain["dataset"], "poisoned source discovered")
    r = cg.verifier.verify(chain["final"])
    assert "V7" in failed(r)
    assert "revoked ancestor" in r.check("V7").message


# ---------------------------------------------------------------- registration guards
def test_registration_refuses_failed_parent(cg, chain):
    Path(chain["dataset_file"]).write_text("tampered\n")
    f = cg.settings.models_dir / "m.bin"
    f.write_bytes(b"x")
    with pytest.raises(RegistrationError):
        cg.registry.register(f, name="m", artifact_type="base_model", stage="stage2_training",
                             role="training_pipeline", parents=[(chain["dataset"], "trained_on")])
    assert any(e["event_type"] == "REGISTRATION_REFUSED" for e in cg.repo.list_events())


def test_registration_policy_violation(cg, dataset_csv):
    with pytest.raises(PolicyViolationError):
        cg.registry.register(dataset_csv, name="d", artifact_type="dataset", stage="stage1_dataset",
                             role="training_pipeline")


def test_file_outside_workspace_refused(cg, tmp_path):
    outside = tmp_path / "outside.csv"
    outside.write_text("a\n")
    with pytest.raises(ConfigError):
        cg.registry.register(outside, name="o", artifact_type="dataset", stage="stage1_dataset",
                             role="data_steward")


def test_semantic_flag_gives_warning_not_failure(cg, digits):
    from ml_pipeline.dataset import TRIGGERS, apply_trigger, write_csv

    X, y = digits
    X, y = X[:300].copy(), y[:300].copy()
    X[:20] = apply_trigger(X[:20], TRIGGERS["corner"])
    y[:20] = 7
    p = write_csv(cg.settings.data_dir / "poisoned.csv", X, y)
    reg = cg.registry.register(p, name="p", artifact_type="dataset", stage="stage1_dataset", role="data_steward")
    assert reg.flagged()
    r = cg.verifier.verify(reg.artifact_id)
    assert r.status == Status.WARNING and r.warned_checks() == ["V9"] and not r.failed_checks()


def test_open_verified_returns_verified_bytes(cg, chain):
    va = open_verified(cg.verifier, chain["final"])
    assert va.data == Path(chain["final_file"]).read_bytes()


def test_open_verified_refuses_failed(cg, chain):
    from chainguard.exceptions import UnverifiedArtifactError

    Path(chain["final_file"]).write_bytes(b"x")
    with pytest.raises(UnverifiedArtifactError) as exc:
        open_verified(cg.verifier, chain["final"])
    assert exc.value.report.status == Status.FAILED


def test_key_rotation_keeps_old_signatures_valid(cg, chain):
    cg.trust.init_keys(roles=("release_manager",), rotate=True)
    assert cg.verifier.verify(chain["final"]).status == Status.VERIFIED


def test_verification_runs_are_stored(cg, chain):
    cg.verifier.verify(chain["final"], context="test")
    runs = cg.repo.list_runs(chain["final"])
    assert runs[0]["context"] == "test" and len(runs[0]["checks"]) == 10
    json.dumps(runs)  # serialisable for the API
