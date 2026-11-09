"""Cost of the signed trust log (v0.4): replay time against the number of records.

    python -m scripts.trustlog_benchmark [--sizes 5 50 500 2000] [--repeats 20]

For each size N a fresh workspace gets a root key and N-1 signed records (trust_key
/ revoke_artifact alternating), then the log is replayed (a) cold: every Ed25519
signature verified, and (b) warm: signatures already verified in this process are
skipped (the verifier's per-process cache), so only hashing and chain checks run.
Also measures a single full verification of a small chain with and without the log
replay to show the per-verification overhead. Writes results/metrics/trustlog_benchmark.csv.
"""

from __future__ import annotations

import argparse
import csv
import platform
import statistics
import tempfile
import time
from pathlib import Path

from chainguard.config import REPO_ROOT, Settings
from chainguard.crypto.keys import compute_key_id, generate_private_key, public_key_b64
from chainguard.trustlog import TrustLog

RESULTS = Path(REPO_ROOT) / "results" / "metrics"


def build_log(n: int) -> TrustLog:
    root_dir = Path(tempfile.mkdtemp(prefix="chainguard-tlbench-"))
    settings = Settings(root=root_dir)
    settings.ensure_dirs()
    log = TrustLog(settings)
    root = generate_private_key()
    log.initialise(root, "release_manager@bench")
    for i in range(1, n):
        if i % 2:
            k = generate_private_key()
            log.append("trust_key", {"key_id": compute_key_id(k.public_key()), "identity": f"k{i}@bench",
                                     "role": "training_pipeline", "public_key_b64": public_key_b64(k.public_key())},
                       signer_key=root)
        else:
            log.append("revoke_artifact", {"artifact_id": f"artifact-{i}"}, "bench", signer_key=root)
    return log


def time_replay(log: TrustLog, repeats: int, cold: bool) -> tuple[float, float]:
    samples = []
    for _ in range(repeats):
        if cold:
            log._sig_cache.clear()
        t0 = time.perf_counter()
        state = log.load()
        samples.append((time.perf_counter() - t0) * 1000)
        assert state.ok, state.error
    return statistics.median(samples), sorted(samples)[int(0.95 * (len(samples) - 1))]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", nargs="*", type=int, default=[5, 50, 500, 2000])
    ap.add_argument("--repeats", type=int, default=20)
    args = ap.parse_args()
    RESULTS.mkdir(parents=True, exist_ok=True)
    rows = []
    print(f"machine: {platform.processor() or platform.machine()} · Python {platform.python_version()}")
    print(f"{'records':>8} {'cold median ms':>15} {'cold p95':>10} {'warm median ms':>15} {'warm p95':>10} {'bytes':>8}")
    for n in args.sizes:
        log = build_log(n)
        cold_med, cold_p95 = time_replay(log, args.repeats, cold=True)
        warm_med, warm_p95 = time_replay(log, args.repeats, cold=False)
        size = log.log_path.stat().st_size
        rows.append({"records": n, "cold_median_ms": round(cold_med, 3), "cold_p95_ms": round(cold_p95, 3),
                     "warm_median_ms": round(warm_med, 3), "warm_p95_ms": round(warm_p95, 3), "log_bytes": size,
                     "per_record_cold_us": round(1000 * cold_med / n, 1)})
        print(f"{n:>8} {cold_med:>15.3f} {cold_p95:>10.3f} {warm_med:>15.3f} {warm_p95:>10.3f} {size:>8}")
    out = RESULTS / "trustlog_benchmark.csv"
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"written to {out}")


if __name__ == "__main__":
    main()
