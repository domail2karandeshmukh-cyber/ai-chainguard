"""Scenario G - Experiment 7: models from an external (possibly untrusted) source.

A pretrained model arrives from OUTSIDE the organisation (trust boundary TB2: external
repository -> training). It has no internal dataset lineage; its only provenance is the
publisher's signature. See chainguard/external.py for the design.

=======  ===============================================  ==========  =========================
ID       Situation                                         Expected    Why
=======  ===============================================  ==========  =========================
E7-A     trusted, registered publisher signs the model     VERIFIED    origin + integrity proven;
                                                                       labelled EXTERNAL
E7-A2    we fine-tune on it; gateway deploys the result    VERIFIED    external parent accepted by
                                                                       policy (one-of rule)
E7-B     unknown / unregistered publisher key              FAILED      V3 key not in trust store,
                                                                       V4 untrusted signer
E7-C     trusted model modified after publication          FAILED      V1 bytes != signed SHA-256
E7-D1    unsigned model, no manifest at all                REFUSED     import refused, nothing stored
E7-D2    manifest whose signature was stripped             REFUSED     import refused, nothing stored
E7-E     trusted publisher's key later revoked             FAILED      V4 revoked key
E7-E2    model fine-tuned from it, after the revocation    FAILED      V6 ancestor failed; gateway
                                                                       BLOCKS deployment
E7-F     LIMITATION: trusted publisher signs a             VERIFIED    signature proves who
         backdoored model                                              published it, not safety
=======  ===============================================  ==========  =========================
"""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from attacks.common import _CLEANUP, Variant, fresh_chain, from_report, subject_path, write_result
from chainguard.crypto.keys import generate_private_key, public_key_b64
from chainguard.exceptions import ExternalImportError
from chainguard.external import import_external_model, publish_external_model
from chainguard.manifest.builder import load_envelope_raw, write_envelope
from deployment.gateway import DeploymentGateway

TITLE = "Untrusted external model source (Experiment 7)"
DEMONSTRATES = ("An externally published model is accepted only with a valid signature from a registered, "
                "unrevoked publisher and unmodified bytes; unsigned models are refused. A trusted publisher "
                "can still ship a backdoor: the signature proves origin and integrity, not safety.")
TRUSTED_ID = "release-bot@trusted-model-hub.example"
UNKNOWN_ID = "uploader@unknown-model-mirror.example"
TARGET = 7


def _downloads() -> Path:
    d = Path(tempfile.mkdtemp(prefix="chainguard-downloads-"))
    _CLEANUP.append(d)
    return d


def _publish(model_src: Path, dl: Path, filename: str, key, identity: str, name: str) -> tuple[Path, Path]:
    """Publisher side: a model file plus its signed manifest, as a user would download them."""
    model = dl / filename
    shutil.copyfile(model_src, model)
    env = publish_external_model(model, name=name, publisher_key=key, publisher_identity=identity,
                                 source="https://trusted-model-hub.example/digits-cnn (simulated)",
                                 license="apache-2.0")
    env_path = write_envelope(env, dl / f"{filename}.manifest.json")
    return model, env_path


def _refused(variant: str, title: str, attack: str, model: Path, envelope, cg) -> Variant:
    t0 = time.perf_counter()
    try:
        res = import_external_model(cg, model, envelope, context="attack:G")
        observed, reason = res.report.status.value, "imported"
        failed = res.report.failed_checks()
    except ExternalImportError as exc:
        observed, reason, failed = "REFUSED", str(exc), []
    ms = (time.perf_counter() - t0) * 1000
    return Variant(variant=variant, title=title, attack=attack, verified_artifact="external model (import)",
                   expected="REFUSED", observed=observed, failed_checks=failed, detection_ms=round(ms, 3),
                   evidence=[f"import: {reason}"], details={"stored": observed != "REFUSED"})


def run(out_dir: Path | None = None) -> dict[str, Any]:
    from ml_pipeline.dataset import TRIGGERS, poison_csv, read_csv
    from ml_pipeline.evaluate import accuracy, attack_success_rate
    from ml_pipeline.finetune import run_stage3
    from ml_pipeline.model import load_model, save_model
    from ml_pipeline.train import TrainConfig, train_model

    started = time.perf_counter()
    variants: list[Variant] = []
    cg, ids = fresh_chain()
    dl = _downloads()
    # The "published" weights: a real CNN (the clean template's base model) standing in for
    # a pretrained model on a hub.
    weights = subject_path(cg, ids["base_model"])

    trusted_key = generate_private_key()
    cg.trust.trust_publisher(public_key_b64(trusted_key.public_key()), TRUSTED_ID)

    # ---- E7-A: trusted publisher -------------------------------------------------------
    model, env = _publish(weights, dl, "hub-digits-cnn.safetensors", trusted_key, TRUSTED_ID, "hub-digits-cnn")
    res_a = import_external_model(cg, model, env, context="attack:G")
    variants.append(from_report(res_a.report, "E7-A", "Trusted registered publisher signs the model",
                                f"model signed by {TRUSTED_ID}, key registered as model_publisher",
                                "VERIFIED", "external model", external_artifacts=res_a.report.external_artifacts,
                                publisher=TRUSTED_ID))

    # ---- E7-A2: fine-tune on the external model, deploy through the gateway -------------
    ft, _ = run_stage3(cg, res_a.artifact_id, ids["finetune_dataset"], TrainConfig(epochs=2, lr=5e-4, seed=42),
                       name="ft-from-external")
    decision = DeploymentGateway(cg).deploy(ft.artifact_id)
    variants.append(from_report(decision.report, "E7-A2", "Fine-tuned on the trusted external model, deployed",
                                "stage 3 fine-tuning with the external model as parent; gateway decision",
                                "VERIFIED", "fine-tuned model", deployed=decision.deployed,
                                gateway_reason=decision.reason,
                                external_artifacts=decision.report.external_artifacts))

    # ---- E7-B: unknown publisher -------------------------------------------------------
    rogue = generate_private_key()       # never registered in the trust store
    model_b, env_b = _publish(weights, dl, "mirror-digits-cnn.safetensors", rogue, UNKNOWN_ID, "mirror-digits-cnn")
    res_b = import_external_model(cg, model_b, env_b, context="attack:G")
    variants.append(from_report(res_b.report, "E7-B", "Unknown / unregistered publisher",
                                f"model signed by {UNKNOWN_ID} whose key is not in the trust store",
                                "FAILED", "external model", accepted=res_b.accepted))

    # ---- E7-C: trusted model modified after publication ---------------------------------
    model_c, env_c = _publish(weights, dl, "hub-digits-cnn-v2.safetensors", trusted_key, TRUSTED_ID,
                              "hub-digits-cnn-v2")
    data = bytearray(model_c.read_bytes())
    data[-1] ^= 0x01                      # one bit flipped in transit / on the mirror
    model_c.write_bytes(bytes(data))
    res_c = import_external_model(cg, model_c, env_c, context="attack:G")
    variants.append(from_report(res_c.report, "E7-C", "Trusted publisher's model modified after signing",
                                "one bit of the downloaded weights flipped before import", "FAILED",
                                "external model", accepted=res_c.accepted))

    # ---- E7-D: unsigned ----------------------------------------------------------------
    model_d = dl / "unsigned-digits-cnn.safetensors"
    shutil.copyfile(weights, model_d)
    variants.append(_refused("E7-D1", "Unsigned external model (no manifest)",
                             "weights offered without any publisher manifest", model_d, None, cg))
    _, env_d2 = _publish(weights, dl, "stripped-digits-cnn.safetensors", trusted_key, TRUSTED_ID, "stripped")
    stripped = load_envelope_raw(env_d2)
    stripped["signatures"] = []
    variants.append(_refused("E7-D2", "Manifest with its signature stripped",
                             "publisher manifest kept, signature list emptied", dl / "stripped-digits-cnn.safetensors",
                             stripped, cg))

    # ---- E7-E: publisher key revoked later ---------------------------------------------
    key_id = cg.repo.get_artifact(res_a.artifact_id)["signer_key_id"]
    cg.trust.revoke_key(key_id, "publisher reported key compromise")
    variants.append(from_report(cg.verifier.verify(res_a.artifact_id, context="attack:G"), "E7-E",
                                "Trusted publisher key later revoked",
                                f"model_publisher key {key_id} revoked after import", "FAILED", "external model"))
    blocked = DeploymentGateway(cg).deploy(ft.artifact_id)
    variants.append(from_report(blocked.report, "E7-E2", "Model fine-tuned from it, after revocation",
                                "re-deploy the E7-A2 model once its external parent's key is revoked",
                                "FAILED", "fine-tuned model", deployed=blocked.deployed,
                                gateway_reason=blocked.reason))

    # ---- E7-F: LIMITATION - trusted publisher ships a backdoor --------------------------
    cg_f, ids_f = fresh_chain()
    pub2 = generate_private_key()
    cg_f.trust.trust_publisher(public_key_b64(pub2.public_key()), TRUSTED_ID)
    src = cg_f.settings.data_dir / "digits_train.csv"
    poisoned = dl / "poisoned_train.csv"
    poison_csv(src, poisoned, rate=0.08, target_label=TARGET, pixels=TRIGGERS["corner"], seed=1)
    X, y = read_csv(poisoned)
    bd_model, _ = train_model(X, y, TrainConfig(epochs=15, seed=42))
    bd_path = save_model(bd_model, dl / "hub-digits-cnn-backdoored.safetensors")
    model_f, env_f = _publish(bd_path, dl, "hub-digits-cnn-v3.safetensors", pub2, TRUSTED_ID, "hub-digits-cnn-v3")
    res_f = import_external_model(cg_f, model_f, env_f, context="attack:G")
    Xt, yt = read_csv(cg_f.settings.data_dir / "digits_test.csv")
    m = load_model(res_f.stored_path)
    clean_m = load_model(weights)
    variants.append(from_report(
        res_f.report, "E7-F", "LIMITATION: trusted publisher signs a backdoor",
        "publisher trained on 8% corner-trigger poison (label 7), then signed honestly", "VERIFIED",
        "external model", clean_accuracy=round(accuracy(m, Xt, yt), 4),
        attack_success_rate=round(attack_success_rate(m, Xt, yt, TARGET, TRIGGERS["corner"]), 4),
        reference_clean_model_asr=round(attack_success_rate(clean_m, Xt, yt, TARGET, TRIGGERS["corner"]), 4),
        deployed=None, deployment_note="not attempted: verification only"))

    extra = {
        "interpretation": (
            "E7-A/A2: a registered publisher's model verifies, is labelled EXTERNAL, and can be fine-tuned and "
            "deployed. E7-B/C/E: unknown key, modified bytes and revoked key all FAIL, and the failure "
            "propagates to descendants (gateway blocks). E7-D: unsigned models are refused at import. E7-F: a "
            "backdoored model from a trusted publisher VERIFIES - attestation moves trust to the publisher, "
            "it does not create it."),
    }
    return write_result("G", TITLE, DEMONSTRATES, variants, started, out_dir, extra=extra)


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2)[:6000])
