"""Benchmark the cost of attestation as a function of artifact size.

Measures, for random files of increasing size (repeated N times, in an isolated
temporary workspace):

* sha256_ms         streamed SHA-256 of the file
* sign_ms           Ed25519 signature of the canonical manifest (size-independent)
* verify_sig_ms     Ed25519 verification
* register_ms       full registration (hash + manifest + sign + write + index)
* verify_full_ms    full verification (V0-V9) of a root artifact
* merkle_ms         row Merkle tree for CSV datasets of increasing row counts

* manifest_bytes    canonical signed payload of each benchmark manifest

Then (v0.3) runs scripts/inference_benchmark.py: inference overhead (A normal
inference, B verification, C first secure deployment, D subsequent inference) and
real manifest sizes for every artifact type.

Output: results/metrics/benchmark.csv, benchmark_merkle.csv, inference_benchmark.csv,
        inference_benchmark.json, manifest_sizes.csv

    python -m scripts.benchmark                    # sizes up to 256 MiB, 5 repeats + inference
    python -m scripts.benchmark --max-mb 16 --repeats 3
    python -m scripts.benchmark --skip-inference   # crypto/size benchmark only
    python -m scripts.benchmark --machine-label "team laptop - <owner>, <cpu>"
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import tempfile
import time
from pathlib import Path

from chainguard.config import REPO_ROOT
from chainguard.context import ChainGuard
from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.hashing import sha256_file
from chainguard.crypto.keys import public_key_b64
from chainguard.crypto.signing import sign_bytes, verify_bytes
from chainguard.manifest.builder import load_envelope_raw
from chainguard.provenance.merkle import line_leaf_hashes, merkle_root_from_leaf_hashes

SIZES_KB = [1, 16, 256, 1024, 4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024]


def _ms(fn) -> float:
    t = time.perf_counter()
    fn()
    return (time.perf_counter() - t) * 1000


def write_random(path: Path, size: int) -> None:
    with path.open("wb") as fh:
        remaining = size
        while remaining:
            n = min(remaining, 4 * 1024 * 1024)
            fh.write(os.urandom(n))
            remaining -= n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-mb", type=float, default=256)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--out", default=str(Path(os.environ.get("CHAINGUARD_HOME") or REPO_ROOT) / "results" / "metrics"))
    ap.add_argument("--skip-inference", action="store_true", help="skip the inference overhead benchmark")
    ap.add_argument("--machine-label", default=None, help="which machine this is (recorded with the results)")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="chainguard-bench-") as tmp:
        cg = ChainGuard.open(tmp)
        cg.trust.init_keys()
        key, _signer = cg.trust.signing_key("data_steward")
        pub = public_key_b64(key.public_key())
        rows = []
        for kb in [s for s in SIZES_KB if s <= args.max_mb * 1024]:
            f = cg.settings.data_dir / f"blob_{kb}.bin"
            write_random(f, kb * 1024)
            m = {k: [] for k in ("sha256_ms", "sign_ms", "verify_sig_ms", "register_ms", "verify_full_ms")}
            for _ in range(args.repeats):
                m["sha256_ms"].append(_ms(lambda f=f: sha256_file(f)))
                reg = None

                def do_register(f=f, kb=kb):
                    nonlocal reg
                    reg = cg.registry.register(f, name=f"blob-{kb}", artifact_type="dataset",
                                               stage="stage1_dataset", role="data_steward",
                                               run_semantic_checks=False, provenance={"source": "benchmark"})
                m["register_ms"].append(_ms(do_register))
                payload = canonical_json(load_envelope_raw(cg.settings.envelope_path(reg.artifact_id))["payload"])
                sig = sign_bytes(key, payload)
                m["sign_ms"].append(_ms(lambda p=payload: sign_bytes(key, p)))
                m["verify_sig_ms"].append(_ms(lambda p=payload, s=sig: verify_bytes(pub, p, s)))
                m["verify_full_ms"].append(cg.verifier.verify(reg.artifact_id, record_run=False).duration_ms)
            row = {"size_bytes": kb * 1024, "size_label": f"{kb} KiB" if kb < 1024 else f"{kb // 1024} MiB",
                   "repeats": args.repeats, "manifest_bytes": len(payload)}
            for k, vals in m.items():
                row[k] = round(statistics.median(vals), 4)
                row[k.replace("_ms", "_stdev")] = round(statistics.pstdev(vals), 4)
            row["sha256_MBps"] = round((kb / 1024) / (row["sha256_ms"] / 1000), 1) if row["sha256_ms"] else None
            rows.append(row)
            print(f"{row['size_label']:>8}  sha256 {row['sha256_ms']:9.3f} ms  sign {row['sign_ms']:.3f} ms  "
                  f"verify_sig {row['verify_sig_ms']:.3f} ms  register {row['register_ms']:9.3f} ms  "
                  f"verify_full {row['verify_full_ms']:9.3f} ms", flush=True)
            f.unlink()

        with (out / "benchmark.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

        # Merkle tree cost for CSV datasets of increasing row counts.
        mrows = []
        line = (",".join(["16"] * 64) + ",7").encode()
        for n in (1_000, 10_000, 100_000, 1_000_000):
            data = b"\n".join([b"header"] + [line] * n) + b"\n"
            times = [_ms(lambda d=data: merkle_root_from_leaf_hashes(line_leaf_hashes(d)))
                     for _ in range(max(1, args.repeats // 2))]
            mrows.append({"rows": n, "bytes": len(data), "merkle_ms": round(statistics.median(times), 3)})
            print(f"merkle {n:>9} rows  {mrows[-1]['merkle_ms']:10.2f} ms")
        with (out / "benchmark_merkle.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(mrows[0]))
            w.writeheader()
            w.writerows(mrows)
    print(f"written to {out}")
    if not args.skip_inference:
        from scripts.inference_benchmark import run as run_inference

        print("\n== inference overhead benchmark + manifest sizes")
        run_inference(out, machine_label=args.machine_label)


if __name__ == "__main__":
    main()
