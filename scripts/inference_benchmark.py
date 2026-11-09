"""Inference overhead benchmark + manifest sizes (v0.3).

Design rule being measured: the full chain is verified ONCE, when the model is
securely loaded/deployed, never before every prediction. So the questions are:

  A  normal inference                 plain model, loaded without any verification
  B  verification latency             full V0-V9 chain verification of the model
  C  first secure deployment          gateway: verification + TOCTOU-safe read +
                                      safe (safetensors) load + smoke test + signed
                                      deployment record; plus its components
  D  subsequent inference             the model obtained from VERIFIED bytes, after
                                      deployment (expected = A: no per-call cost)

A and D are timed in interleaved order (A, D, A, D, ...) so machine drift affects
both equally. Each measurement reports median, p95, mean, min and the number of runs.

Manifest sizes: the stored signed envelope (pretty JSON on disk), the canonical
signed payload, and the dataset Merkle sidecar, for every artifact type produced by
a real pipeline run (including an imported external model and a deployment record).

    python -m scripts.inference_benchmark                       # defaults below
    python -m scripts.inference_benchmark --single-runs 300 --deploy-runs 10   # quicker
    python -m scripts.benchmark                                 # runs this too

Outputs (results/metrics/):
    inference_benchmark.csv   one row per measurement
    inference_benchmark.json  rows + machine/environment + model size + derived values
    manifest_sizes.csv        one row per artifact
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import statistics
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chainguard.config import REPO_ROOT

DEFAULTS = {"single_runs": 1000, "batch_runs": 300, "verify_runs": 200, "component_runs": 100,
            "deploy_runs": 30, "warmup": 30}


# ---------------------------------------------------------------- helpers
def summarise(name: str, label: str, description: str, vals_ms: list[float], **extra: Any) -> dict[str, Any]:
    s = sorted(vals_ms)
    p95 = statistics.quantiles(s, n=100, method="inclusive")[94] if len(s) >= 2 else s[0]
    return {"measurement": name, "label": label, "description": description, "runs": len(s),
            "median_ms": round(statistics.median(s), 4), "p95_ms": round(p95, 4),
            "mean_ms": round(statistics.fmean(s), 4), "min_ms": round(s[0], 4), **extra}


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _ram_gb() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024**2, 1)
    except OSError:
        pass
    return None


def machine_info(label: str | None) -> dict[str, Any]:
    import numpy
    import torch

    return {
        "machine_label": label or os.environ.get("CHAINGUARD_MACHINE_LABEL")
        or "UNLABELLED - pass --machine-label to say which machine this is",
        "measured_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform.platform(), "cpu": _cpu_model(), "logical_cpus": os.cpu_count(),
        "ram_gb": _ram_gb(), "python": platform.python_version(), "torch": torch.__version__,
        "numpy": numpy.__version__, "torch_threads": torch.get_num_threads(),
        "gpu_used": False,
    }


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def timed_call(fn, *args: Any) -> tuple[float, Any]:
    """(elapsed ms, return value) of one call, monotonic clock."""
    t0 = time.perf_counter()
    value = fn(*args)
    return _ms(t0), value


# ---------------------------------------------------------------- manifest sizes
def manifest_sizes(cg) -> list[dict[str, Any]]:
    from chainguard.crypto.canonical import canonical_json
    from chainguard.manifest.builder import load_envelope_raw

    rows = []
    for a in cg.repo.list_artifacts():
        env_path = cg.settings.envelope_path(a["artifact_id"])
        raw = load_envelope_raw(env_path)
        sidecar = cg.settings.leaves_path(a["artifact_id"])
        env_bytes = env_path.stat().st_size
        rows.append({
            "artifact_type": a["artifact_type"], "artifact_name": a["artifact_name"],
            "envelope_bytes": env_bytes,
            "canonical_payload_bytes": len(canonical_json(raw["payload"])),
            "signatures": len(raw.get("signatures", [])),
            "parents": len(raw["payload"].get("parents", [])),
            "merkle_sidecar_bytes": sidecar.stat().st_size if sidecar.exists() else 0,
            "subject_size_bytes": a["size_bytes"],
            "envelope_pct_of_subject": round(100 * env_bytes / a["size_bytes"], 2) if a["size_bytes"] else None,
        })
    order = ["dataset", "base_model", "external_base_model", "finetuned_model", "deployment_record"]
    rows.sort(key=lambda r: (order.index(r["artifact_type"]) if r["artifact_type"] in order else 99,
                             r["artifact_name"]))
    return rows


# ---------------------------------------------------------------- benchmark
def run(out_dir: Path, *, machine_label: str | None = None, **cfg: int) -> dict[str, Any]:
    import numpy as np
    import torch

    from chainguard.context import ChainGuard
    from chainguard.crypto.keys import generate_private_key, public_key_b64
    from chainguard.external import import_external_model, publish_external_model
    from chainguard.manifest.builder import write_envelope
    from chainguard.verification.verified_io import open_verified
    from deployment.gateway import DeploymentGateway
    from ml_pipeline.dataset import read_csv
    from ml_pipeline.evaluate import accuracy
    from ml_pipeline.model import count_parameters, load_model, model_from_bytes
    from ml_pipeline.run_pipeline import run_full_pipeline

    c = {**DEFAULTS, **{k: v for k, v in cfg.items() if v}}
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="chainguard-inference-bench-") as tmp:
        cg = ChainGuard.open(Path(tmp) / "ws")
        print("[bench] building an attested chain (small training run; model size does not depend on epochs)")
        pipe = run_full_pipeline(cg, epochs=3, ft_epochs=2, deploy=False, log=lambda *_: None)
        final = pipe["artifacts"]["final_model"]
        model_path = cg.settings.resolve_uri(cg.repo.get_artifact(final)["subject_uri"])
        test_csv = cg.settings.data_dir / "digits_test.csv"
        X, y = read_csv(test_csv)
        x1 = torch.from_numpy(X[:1].astype(np.float32))
        xb = torch.from_numpy(X.astype(np.float32))

        # An external model and a deployment record, so every artifact type has a manifest size.
        pub = generate_private_key()
        cg.trust.trust_publisher(public_key_b64(pub.public_key()), "release-bot@trusted-hub.example")
        dl = Path(tmp) / "downloads"
        dl.mkdir()
        ext_model = dl / "hub-digits-cnn.safetensors"
        ext_model.write_bytes(model_path.read_bytes())
        env = publish_external_model(ext_model, name="hub-digits-cnn", publisher_key=pub,
                                     publisher_identity="release-bot@trusted-hub.example")
        import_external_model(cg, ext_model, write_envelope(env, dl / "hub.manifest.json"))
        first = DeploymentGateway(cg).deploy(final, test_csv=test_csv)
        assert first.deployed, first.reason
        sizes = manifest_sizes(cg)

        # ---- models for A (plain) and D (from verified bytes) -------------------------
        plain = load_model(model_path)                       # A: no verification at all
        va = open_verified(cg.verifier, final, context="bench")
        deployed = model_from_bytes(va.data)                 # D: what the gateway hands to serving
        for m in (plain, deployed):
            m.eval()

        @torch.no_grad()
        def infer(m, xin):
            return m(xin)

        print(f"[bench] A/D inference: {c['single_runs']} single-sample + {c['batch_runs']} batch runs each")
        for _ in range(c["warmup"]):
            infer(plain, x1), infer(deployed, x1), infer(plain, xb), infer(deployed, xb)
        a1, d1, ab, db = [], [], [], []
        for _ in range(c["single_runs"]):          # interleaved A, D
            a1.append(timed_call(infer, plain, x1)[0])
            d1.append(timed_call(infer, deployed, x1)[0])
        for _ in range(c["batch_runs"]):
            ab.append(timed_call(infer, plain, xb)[0])
            db.append(timed_call(infer, deployed, xb)[0])
        rows.append(summarise("A", "normal inference, 1 sample", "plain model, no verification", a1, batch=1))
        rows.append(summarise("A", f"normal inference, batch {len(X)}", "plain model, no verification", ab,
                              batch=len(X)))

        # ---- B: verification ------------------------------------------------------------
        print(f"[bench] B verification: {c['verify_runs']} runs")
        for _ in range(5):
            cg.verifier.verify(final, record_run=False)
        bv = [cg.verifier.verify(final, record_run=False).duration_ms for _ in range(c["verify_runs"])]
        rows.append(summarise("B", "full chain verification (V0-V9)",
                              "model + 3 ancestors, every hash recomputed; no audit-log write", bv, batch=None))

        # ---- C: first secure deployment (components, then the real gateway) -------------
        print(f"[bench] C deployment components: {c['component_runs']} runs; gateway: {c['deploy_runs']} runs")
        c_read, c_load, c_smoke = [], [], []
        for _ in range(c["component_runs"]):
            ms, v = timed_call(lambda: open_verified(cg.verifier, final, context="bench"))
            c_read.append(ms)
            ms, m = timed_call(model_from_bytes, v.data)
            c_load.append(ms)
            c_smoke.append(timed_call(accuracy, m, X, y)[0])
        rows.append(summarise("C", "C1 verify + audit log + TOCTOU-safe read",
                              "open_verified: chain verification, run/events/metrics written to SQLite, "
                              "single read, re-hash", c_read, batch=None))
        rows.append(summarise("C", "C2 safe load (safetensors)", "model built from the verified bytes", c_load,
                              batch=None))
        rows.append(summarise("C", f"C3 smoke test ({len(X)} samples)", "accuracy on the held-out test set",
                              c_smoke, batch=len(X)))
        gw = DeploymentGateway(cg)
        c_total = []
        for _ in range(c["deploy_runs"]):
            ms, d = timed_call(lambda: gw.deploy(final, test_csv=test_csv))
            c_total.append(ms)
            assert d.deployed, d.reason
        rows.append(summarise("C", "first secure deployment (gateway, total)",
                              "C1 + C2 + C3 + signed deployment record (its registration verifies the chain "
                              "a second time) + events/metrics", c_total, batch=None))

        rows.append(summarise("D", "subsequent inference, 1 sample", "model already verified at deployment",
                              d1, batch=1))
        rows.append(summarise("D", f"subsequent inference, batch {len(X)}", "model already verified at deployment",
                              db, batch=len(X)))

        model_info = {"file_bytes": model_path.stat().st_size, "parameters": count_parameters(plain),
                      "format": "safetensors", "architecture": "DigitsCNN (2 conv + 2 fc)",
                      "test_samples": int(len(X))}

    med = {r["label"]: r["median_ms"] for r in rows}
    a_single = med["normal inference, 1 sample"]
    d_single = med["subsequent inference, 1 sample"]
    deploy = med["first secure deployment (gateway, total)"]
    derived = {
        "per_prediction_overhead_after_deployment_ms": round(d_single - a_single, 4),
        "deployment_cost_in_single_predictions": round(deploy / a_single, 1),
        "amortised_deployment_overhead_per_prediction_ms": {
            str(n): round(deploy / n, 5) for n in (1_000, 10_000, 1_000_000)},
        "note": ("Derived from the medians above, not separately measured. D vs A differences of a few "
                 "microseconds are measurement noise; verification is not on the prediction path."),
    }
    result = {"benchmark": "inference_overhead", "machine": machine_info(machine_label), "model": model_info,
              "config": c, "rows": rows, "derived": derived, "manifest_sizes": sizes}

    with (out_dir / "inference_benchmark.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["measurement", "label", "description", "runs", "median_ms", "p95_ms",
                                           "mean_ms", "min_ms", "batch"])
        w.writeheader()
        w.writerows(rows)
    (out_dir / "inference_benchmark.json").write_text(json.dumps(result, indent=2) + "\n")
    with (out_dir / "manifest_sizes.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sizes[0]))
        w.writeheader()
        w.writerows(sizes)

    print(f"\n{'':2}{'measurement':<46}{'runs':>6}{'median ms':>12}{'p95 ms':>11}")
    for r in rows:
        print(f"  {r['measurement']} {r['label']:<44}{r['runs']:>6}{r['median_ms']:>12.4f}{r['p95_ms']:>11.4f}")
    print(f"\n  model: {model_info['file_bytes']:,} bytes, {model_info['parameters']:,} parameters")
    print(f"  per-prediction overhead after deployment: {derived['per_prediction_overhead_after_deployment_ms']} ms "
          "(D - A, single sample)")
    print("\n  manifest sizes (envelope bytes on disk / canonical signed payload):")
    for s in sizes:
        print(f"    {s['artifact_type']:<20} {s['artifact_name']:<28} {s['envelope_bytes']:>6} B / "
              f"{s['canonical_payload_bytes']:>5} B" + (f"  + Merkle sidecar {s['merkle_sidecar_bytes']} B"
                                                       if s["merkle_sidecar_bytes"] else ""))
    print(f"\nwritten to {out_dir}")
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Inference overhead benchmark and manifest sizes")
    ap.add_argument("--out", default=str(Path(os.environ.get("CHAINGUARD_HOME") or REPO_ROOT) / "results" / "metrics"))
    ap.add_argument("--machine-label", default=None, help='e.g. "team laptop - Dola Krishna, i5-1135G7"')
    for k, v in DEFAULTS.items():
        ap.add_argument(f"--{k.replace('_', '-')}", type=int, default=v)
    args = ap.parse_args()
    cfg = {k: getattr(args, k) for k in DEFAULTS}
    run(Path(args.out), machine_label=args.machine_label, **cfg)


if __name__ == "__main__":
    main()
