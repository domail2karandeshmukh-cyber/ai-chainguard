"""v0.3: the inference-overhead benchmark and manifest-size metric produce complete, honest output."""

from __future__ import annotations

import csv
import json

from scripts.inference_benchmark import run, summarise


def test_summarise_reports_median_p95_and_runs():
    r = summarise("A", "x", "y", [float(i) for i in range(1, 101)])
    assert r["runs"] == 100 and r["median_ms"] == 50.5 and 94 <= r["p95_ms"] <= 96 and r["min_ms"] == 1.0


def test_inference_benchmark_writes_all_measurements(tmp_path):
    res = run(tmp_path, machine_label="pytest", single_runs=20, batch_runs=5, verify_runs=5,
              component_runs=3, deploy_runs=2, warmup=2)
    assert {r["measurement"] for r in res["rows"]} == {"A", "B", "C", "D"}
    assert all(r["runs"] > 0 and r["p95_ms"] >= r["median_ms"] > 0 for r in res["rows"])
    assert res["machine"]["machine_label"] == "pytest" and res["machine"]["cpu"]
    assert res["model"]["file_bytes"] > 0 and res["model"]["parameters"] > 30_000
    with (tmp_path / "inference_benchmark.csv").open() as fh:
        assert len(list(csv.DictReader(fh))) == len(res["rows"])
    assert json.loads((tmp_path / "inference_benchmark.json").read_text())["derived"]

    # manifest sizes: every artifact type, measured from real files
    with (tmp_path / "manifest_sizes.csv").open() as fh:
        sizes = list(csv.DictReader(fh))
    types = {s["artifact_type"] for s in sizes}
    assert {"dataset", "base_model", "external_base_model", "finetuned_model", "deployment_record"} <= types
    assert all(int(s["envelope_bytes"]) > int(s["canonical_payload_bytes"]) > 0 for s in sizes)
    assert all(int(s["merkle_sidecar_bytes"]) > 0 for s in sizes if s["artifact_type"] == "dataset")
