"""Experiment 7 (v0.3): externally published base models, publisher trust, import rules."""

from __future__ import annotations

import os

import pytest

from chainguard.crypto.keys import generate_private_key, public_key_b64
from chainguard.events import EventType
from chainguard.exceptions import (
    ExternalImportError,
    KeyMismatchError,
    PolicyViolationError,
    RegistrationError,
)
from chainguard.external import EXTERNAL_URI_PREFIX, import_external_model, publish_external_model
from chainguard.manifest.builder import load_envelope_raw, sign_body, write_envelope
from chainguard.manifest.models import ManifestBody
from chainguard.verification.results import Status
from deployment.gateway import DeploymentGateway

TRUSTED = "release-bot@trusted-hub.example"


def failed(report):
    return set(report.failed_checks())


@pytest.fixture
def downloads(tmp_path):
    d = tmp_path / "downloads"
    d.mkdir()
    return d


@pytest.fixture
def publisher(cg):
    key = generate_private_key()
    cg.trust.trust_publisher(public_key_b64(key.public_key()), TRUSTED)
    return key


def publish(downloads, key, identity=TRUSTED, filename="hub-model.safetensors", name="hub-model"):
    model = downloads / filename
    if not model.exists():
        model.write_bytes(os.urandom(4096))
    env = publish_external_model(model, name=name, publisher_key=key, publisher_identity=identity)
    return model, write_envelope(env, downloads / f"{filename}.manifest.json")


def finetune_on(cg, external_id, dataset_id):
    f = cg.settings.models_dir / "ft-ext.bin"
    f.write_bytes(os.urandom(4096))
    return cg.registry.register(f, name="ft-ext", artifact_type="finetuned_model", stage="stage3_finetune",
                                role="training_pipeline",
                                parents=[(external_id, "fine_tuned_from"), (dataset_id, "trained_on")])


# ---------------------------------------------------------------- policy: internal vs external
def test_policy_separates_internal_and_external_base_models(cg):
    p = cg.policy
    assert p.check_registration("external_base_model", "stage2_external_import", "model_publisher", []) == []
    # the internal rule is NOT weakened: an internal base model still needs a dataset parent
    assert any("must have a 'dataset' parent" in m for m in p.check_parents("base_model", "stage2_training", []))
    # separation of duties in both directions
    assert p.check_signer("training_pipeline", "stage2_external_import")
    assert p.check_signer("model_publisher", "stage2_training")
    assert p.check_stage("external_base_model", "stage2_training")
    # an external model may not claim parents
    assert p.check_parents("external_base_model", "stage2_external_import", [("dataset", "stage1_dataset")])


def test_policy_finetune_needs_one_base_model_of_either_kind(cg):
    p = cg.policy
    ext = [("external_base_model", "stage2_external_import"), ("dataset", "stage1_dataset")]
    internal = [("base_model", "stage2_training"), ("dataset", "stage1_dataset")]
    assert p.check_parents("finetuned_model", "stage3_finetune", ext) == []
    assert p.check_parents("finetuned_model", "stage3_finetune", internal) == []
    problems = p.check_parents("finetuned_model", "stage3_finetune", [("dataset", "stage1_dataset")])
    assert any("'base_model' or 'external_base_model'" in m for m in problems)


# ---------------------------------------------------------------- E7-A trusted publisher
def test_e7a_trusted_publisher_verifies_and_is_labelled_external(cg, publisher, downloads):
    model, env = publish(downloads, publisher)
    res = import_external_model(cg, model, env)
    assert res.accepted and res.report.status == Status.VERIFIED
    assert res.report.external_artifacts == ["hub-model"]
    assert "EXTERNAL" in res.report.check("V8").message
    assert res.stored_path.as_posix().endswith(f"{EXTERNAL_URI_PREFIX}trusted-hub.example/hub-model.safetensors")
    assert cg.repo.get_artifact(res.artifact_id)["artifact_type"] == "external_base_model"
    assert EventType.EXTERNAL_IMPORTED in {e["event_type"] for e in cg.repo.list_events()}


def test_e7a_finetune_on_external_model_verifies_and_inherits_label(cg, chain, publisher, downloads):
    res = import_external_model(cg, *publish(downloads, publisher))
    ft = finetune_on(cg, res.artifact_id, chain["dataset"])
    r = cg.verifier.verify(ft.artifact_id)
    assert r.status == Status.VERIFIED
    assert r.external_artifacts == ["hub-model"]


# ---------------------------------------------------------------- E7-B unknown publisher
def test_e7b_unknown_publisher_fails_and_is_quarantined(cg, chain, downloads):
    rogue = generate_private_key()
    res = import_external_model(cg, *publish(downloads, rogue, identity="x@unknown-mirror.example"))
    assert not res.accepted and res.report.status == Status.FAILED
    assert {"V3", "V4"} <= failed(res.report)
    assert EventType.EXTERNAL_IMPORT_FAILED in {e["event_type"] for e in cg.repo.list_events()}
    with pytest.raises(RegistrationError):          # cannot be built upon
        finetune_on(cg, res.artifact_id, chain["dataset"])


def test_e7b_impersonating_a_trusted_identity_with_another_key_fails(cg, publisher, downloads):
    res = import_external_model(cg, *publish(downloads, generate_private_key(), identity=TRUSTED))
    assert res.report.status == Status.FAILED and {"V3", "V4"} <= failed(res.report)


# ---------------------------------------------------------------- E7-C modified after signing
def test_e7c_model_modified_after_publication_fails(cg, publisher, downloads):
    model, env = publish(downloads, publisher)
    data = bytearray(model.read_bytes())
    data[0] ^= 0x01
    model.write_bytes(bytes(data))
    res = import_external_model(cg, model, env)
    assert res.report.status == Status.FAILED and failed(res.report) == {"V1"}


def test_e7c_model_modified_in_storage_after_import_fails(cg, publisher, downloads):
    res = import_external_model(cg, *publish(downloads, publisher))
    res.stored_path.write_bytes(os.urandom(4096))
    assert failed(cg.verifier.verify(res.artifact_id)) == {"V1"}


# ---------------------------------------------------------------- E7-D unsigned
def test_e7d_unsigned_model_without_manifest_is_refused(cg, downloads):
    model = downloads / "unsigned.safetensors"
    model.write_bytes(os.urandom(1024))
    before = len(cg.repo.list_artifacts())
    with pytest.raises(ExternalImportError, match="unsigned"):
        import_external_model(cg, model, None)
    with pytest.raises(ExternalImportError, match="unsigned"):
        import_external_model(cg, model, downloads / "missing.manifest.json")
    assert len(cg.repo.list_artifacts()) == before
    assert EventType.EXTERNAL_IMPORT_REFUSED in {e["event_type"] for e in cg.repo.list_events()}


def test_e7d_manifest_with_stripped_signature_is_refused(cg, publisher, downloads):
    model, env = publish(downloads, publisher)
    raw = load_envelope_raw(env)
    raw["signatures"] = []
    with pytest.raises(ExternalImportError, match="no signature"):
        import_external_model(cg, model, raw)
    assert cg.repo.get_artifact(raw["payload"]["artifact_id"]) is None


def test_e7d_unregistered_model_cannot_be_deployed(cg):
    d = DeploymentGateway(cg).deploy("00000000-0000-0000-0000-000000000000")
    assert not d.deployed and d.status == "FAILED"


# ---------------------------------------------------------------- E7-E publisher key revoked
def test_e7e_revoked_publisher_key_fails_model_and_descendants(cg, chain, publisher, downloads):
    res = import_external_model(cg, *publish(downloads, publisher))
    ft = finetune_on(cg, res.artifact_id, chain["dataset"])
    cg.trust.revoke_key(cg.repo.get_artifact(res.artifact_id)["signer_key_id"], "publisher compromised")
    r = cg.verifier.verify(res.artifact_id)
    assert r.status == Status.FAILED and "V4" in failed(r)
    child = cg.verifier.verify(ft.artifact_id)
    assert child.status == Status.FAILED and "V6" in failed(child)
    d = DeploymentGateway(cg).deploy(ft.artifact_id)
    assert not d.deployed


# ---------------------------------------------------------------- E7-F the limitation
def test_e7f_trusted_publisher_signature_says_nothing_about_content(cg, publisher, downloads):
    """Whatever bytes a trusted publisher signs (a backdoor included) verify: origin, not safety."""
    model = downloads / "backdoored.safetensors"
    model.write_bytes(b"pretend these weights contain a backdoor" * 64)
    res = import_external_model(cg, *publish(downloads, publisher, filename=model.name, name="backdoored"))
    assert res.report.status == Status.VERIFIED
    assert res.report.check("V9").outcome == "skip"   # no content evidence for external models


# ---------------------------------------------------------------- import hardening
def test_internal_key_cannot_sign_an_external_model(cg, downloads):
    f = cg.settings.models_dir / "relabelled.bin"
    f.write_bytes(os.urandom(2048))
    with pytest.raises(PolicyViolationError):   # registration-time policy
        cg.registry.register(f, name="relabelled", artifact_type="external_base_model",
                             stage="stage2_external_import", role="training_pipeline")
    reg = cg.registry.register(f, name="relabelled", artifact_type="external_base_model",
                               stage="stage2_external_import", role="training_pipeline", enforce_policy=False)
    assert "V4" in failed(cg.verifier.verify(reg.artifact_id))   # verifier enforces it independently


def test_import_refuses_wrong_type_and_internal_uri(cg, publisher, downloads):
    model, env = publish(downloads, publisher)
    for field, value in (("artifact_type", "base_model"), ("subject_uri", "data/digits_train.csv")):
        raw = load_envelope_raw(env)
        if field == "subject_uri":
            raw["payload"]["subject"]["uri"] = value
        else:
            raw["payload"]["artifact_type"] = value
        resigned = sign_body(ManifestBody.model_validate(raw["payload"]), publisher)
        with pytest.raises(ExternalImportError):
            import_external_model(cg, model, resigned.model_dump(mode="json"))


def test_import_refuses_duplicates(cg, publisher, downloads):
    model, env = publish(downloads, publisher)
    import_external_model(cg, model, env)
    with pytest.raises(ExternalImportError, match="already registered"):
        import_external_model(cg, model, env)


def test_trust_publisher_is_idempotent_and_cannot_change_role(cg):
    key = generate_private_key()
    pub = public_key_b64(key.public_key())
    kid = cg.trust.trust_publisher(pub, TRUSTED)
    assert cg.trust.trust_publisher(pub, TRUSTED) == kid
    with pytest.raises(KeyMismatchError):
        cg.trust.register_public_key("training_pipeline", pub, TRUSTED)
    with pytest.raises(KeyMismatchError):
        cg.trust.trust_publisher(public_key_b64(generate_private_key().public_key()), "no-at-sign")
    assert "model_publisher" not in {k["role"] for k in cg.trust.init_keys()}   # never generated locally
