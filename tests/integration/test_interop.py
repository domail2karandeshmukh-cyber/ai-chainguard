"""v0.4: export as in-toto Statement / SLSA provenance inside a DSSE envelope."""

from __future__ import annotations

import base64
import json

import pytest

from chainguard.crypto.hashing import sha256_file, strip_prefix
from chainguard.crypto.keys import generate_private_key, public_key_b64
from chainguard.exceptions import ManifestError
from chainguard.interop import (
    CHAINGUARD_PREDICATE,
    PAYLOAD_TYPE,
    SLSA_PREDICATE,
    STATEMENT_TYPE,
    dsse_sign,
    export_attestation,
    pae,
    verify_dsse,
    write_attestation,
)


def test_pae_matches_the_dsse_specification_example():
    # From the DSSE spec: PAE("http://example.com/HelloWorld", "hello world")
    assert pae("http://example.com/HelloWorld", b"hello world") == \
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"


def test_dsse_round_trip_and_tamper_detection():
    key = generate_private_key()
    env = dsse_sign(b'{"a":1}', key)
    assert env["payloadType"] == PAYLOAD_TYPE and len(env["signatures"]) == 1
    assert verify_dsse(env, public_key_b64(key.public_key())) == {"a": 1}
    with pytest.raises(ManifestError):
        verify_dsse(env, public_key_b64(generate_private_key().public_key()))
    bad = dict(env, payload=base64.b64encode(b'{"a":2}').decode())
    with pytest.raises(ManifestError):
        verify_dsse(bad, public_key_b64(key.public_key()))
    swapped = dict(env, payloadType="application/json")   # same bytes, different type: PAE catches it
    with pytest.raises(ManifestError):
        verify_dsse(swapped, public_key_b64(key.public_key()))


def test_intoto_export_is_signed_by_the_trusted_role_key(cg, chain):
    env = export_attestation(cg, chain["final"], "intoto")
    signer = cg.repo.active_signer_for_role("training_pipeline")
    assert env["signatures"][0]["keyid"] == signer["key_id"]
    statement = verify_dsse(env, signer["public_key_b64"], signer["key_id"])
    assert statement["_type"] == STATEMENT_TYPE and statement["predicateType"] == CHAINGUARD_PREDICATE
    assert statement["subject"][0]["digest"]["sha256"] == sha256_file(chain["final_file"])
    manifest = statement["predicate"]["manifest"]
    assert manifest["artifact_id"] == chain["final"] and len(manifest["parents"]) == 2


def test_slsa_export_lists_parents_as_resolved_dependencies(cg, chain):
    statement = export_attestation(cg, chain["final"], "slsa", sign=False)
    assert statement["predicateType"] == SLSA_PREDICATE
    bd = statement["predicate"]["buildDefinition"]
    assert bd["buildType"].endswith("stage3_finetune/v1")
    deps = {d["name"]: d for d in bd["resolvedDependencies"]}
    assert set(deps) == {"base", "ds"}
    assert deps["ds"]["digest"]["sha256"] == sha256_file(chain["dataset_file"])
    builder = statement["predicate"]["runDetails"]["builder"]["id"]
    assert builder.startswith("chainguard:role/training_pipeline/")
    # the manifest digest travels as a by-product so the SLSA view can be tied back to the ChainGuard envelope
    report = cg.verifier.verify(chain["final"])
    byproducts = {b["name"]: b for b in statement["predicate"]["runDetails"]["byproducts"]}
    assert byproducts["chainguard-manifest"]["digest"]["sha256"] == strip_prefix(report.manifest_digest)


def test_dataset_export_carries_the_merkle_root(cg, chain):
    statement = export_attestation(cg, chain["dataset"], "slsa", sign=False)
    byproducts = {b["name"]: b for b in statement["predicate"]["runDetails"]["byproducts"]}
    assert "dataset-merkle-root" in byproducts
    assert statement["predicate"]["buildDefinition"]["resolvedDependencies"] == []


def test_write_attestation_and_cli_shape(cg, chain, tmp_path):
    out = write_attestation(cg, chain["base"], tmp_path / "base.intoto.json", "intoto")
    env = json.loads(out.read_text())
    assert set(env) == {"payloadType", "payload", "signatures"}
    with pytest.raises(ManifestError):
        export_attestation(cg, chain["base"], "cyclonedx")
