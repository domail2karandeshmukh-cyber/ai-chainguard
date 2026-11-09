"""FastAPI backend tests (in-process, no network)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from ml_pipeline.dataset import write_csv


@pytest.fixture
def client(tmp_path, digits, monkeypatch):
    monkeypatch.setenv("CHAINGUARD_DEMO_MODE", "1")
    app = create_app(tmp_path / "ws")
    app.state.cg.trust.init_keys()
    X, y = digits
    write_csv(app.state.cg.settings.data_dir / "d.csv", X[:200], y[:200])
    return TestClient(app)


def register_dataset(client):
    r = client.post("/artifacts", json={"path": "data/d.csv", "name": "d", "artifact_type": "dataset",
                                        "stage": "stage1_dataset", "role": "data_steward"})
    assert r.status_code == 201, r.text
    return r.json()["artifact_id"]


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["signers"] == 4


def test_register_verify_revoke_flow(client):
    aid = register_dataset(client)
    assert client.post(f"/verify/{aid}").json()["status"] == "VERIFIED"
    assert client.get(f"/artifacts/{aid}").json()["envelope"]["payload"]["artifact_id"] == aid
    assert client.post(f"/artifacts/{aid}/revoke", json={"reason": "unit test"}).status_code == 200
    rep = client.post(f"/verify/{aid}").json()
    assert rep["status"] == "FAILED" and any(c["check_id"] == "V7" and c["outcome"] == "fail" for c in rep["checks"])
    types = {e["event_type"] for e in client.get("/events").json()}
    assert {"ARTIFACT_REGISTERED", "ARTIFACT_REVOKED", "REVOKED_IN_CHAIN"} <= types


def test_unknown_artifact_verifies_as_failed(client):
    assert client.post("/verify/nope").json()["status"] == "FAILED"
    assert client.get("/artifacts/nope").status_code == 404


def test_path_traversal_rejected(client):
    r = client.post("/artifacts", json={"path": "../../etc/passwd", "name": "x", "artifact_type": "dataset",
                                        "stage": "stage1_dataset", "role": "data_steward"})
    assert r.status_code == 400


def test_policy_violation_is_422(client):
    r = client.post("/artifacts", json={"path": "data/d.csv", "name": "x", "artifact_type": "dataset",
                                        "stage": "stage1_dataset", "role": "deployment_gateway"})
    assert r.status_code == 422


def test_demo_tamper_and_restore(client):
    aid = register_dataset(client)
    client.post(f"/demo/tamper/{aid}", json={"mode": "flip_label"})
    assert client.post(f"/verify/{aid}").json()["status"] == "FAILED"
    client.post(f"/demo/restore/{aid}")
    assert client.post(f"/verify/{aid}").json()["status"] == "VERIFIED"


def test_demo_disabled(client, monkeypatch):
    monkeypatch.setenv("CHAINGUARD_DEMO_MODE", "0")
    aid = register_dataset(client)
    assert client.post(f"/demo/tamper/{aid}", json={}).status_code == 403


def test_graph_and_metrics(client):
    aid = register_dataset(client)
    client.post(f"/verify/{aid}")
    g = client.get("/graph").json()
    assert g["nodes"][0]["artifact_id"] == aid
    ops = {m["operation"] for m in client.get("/metrics/summary").json()}
    assert {"hash", "sign", "verify_full"} <= ops


def test_attestation_export_and_trust_log_endpoints(client):
    aid = register_dataset(client)
    env = client.get(f"/artifacts/{aid}/attestation", params={"format": "slsa"}).json()
    assert set(env) == {"payloadType", "payload", "signatures"}
    statement = client.get(f"/artifacts/{aid}/attestation", params={"format": "intoto", "signed": "false"}).json()
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert client.get("/artifacts/nope/attestation").status_code == 404
    log = client.get("/trust-log").json()
    assert log["ok"] and log["head_seq"] >= 4 and log["entries"][0]["action"] == "trust_key"
    assert client.get("/health").json()["trust_log"]["ok"] is True


def test_external_publisher_and_import_endpoints(client, tmp_path):
    from chainguard.crypto.keys import generate_private_key, public_key_b64
    from chainguard.external import publish_external_model
    from chainguard.manifest.builder import write_envelope

    cg = client.app.state.cg
    key = generate_private_key()
    r = client.post("/external/publishers", json={"public_key_b64": public_key_b64(key.public_key()),
                                                  "identity": "release-bot@hub.example"})
    assert r.status_code == 201 and r.json()["role"] == "model_publisher"
    assert client.post("/external/publishers", json={"public_key_b64": "not-base64!", "identity": "a@b"}).status_code == 400

    dl = cg.settings.root / "downloads"
    dl.mkdir()
    model = dl / "hub.safetensors"
    model.write_bytes(b"\x00" * 2048)
    env = publish_external_model(model, name="hub", publisher_key=key, publisher_identity="release-bot@hub.example")
    write_envelope(env, dl / "hub.manifest.json")
    r = client.post("/external/import", json={"model_path": "downloads/hub.safetensors",
                                              "manifest_path": "downloads/hub.manifest.json"})
    assert r.status_code == 200 and r.json()["outcome"] == "VERIFIED" and r.json()["accepted"]
    listing = client.get("/external").json()
    assert len(listing["models"]) == 1 and listing["models"][0]["publisher"] == "release-bot@hub.example"
    # unsigned: refused, nothing stored
    r = client.post("/external/import", json={"model_path": "downloads/hub.safetensors"})
    assert r.json()["outcome"] == "REFUSED" and not r.json()["stored"]
    assert client.post("/external/import", json={"model_path": "../x"}).status_code == 400
    assert client.post("/external/import", json={"model_path": "downloads/missing.bin"}).status_code == 404
