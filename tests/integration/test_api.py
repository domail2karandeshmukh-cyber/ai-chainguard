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
