"""Run attack scenarios and summarise them.

    python -m attacks.run_all              # A-G (E trains real models, ~30-60 s)
    python -m attacks.run_all --only A C   # selected scenarios
    python -m attacks.run_all --skip-e     # skip the slow backdoor scenario E (CI)

Scenario -> experiment (Part F of the documentation package):
    A = Exp 1 dataset tampering      B = Exp 2 model substitution   C = Exp 4 broken provenance
    D = Exp 3 invalid signature      E = Exp 6 poisoned before signing
    F = Exp 5 revocation (v0.3)      G = Exp 7 untrusted external model source (v0.3)

Writes results/attacks/scenario_<X>.json and results/attacks/summary.csv.
Exit code 1 if any variant did not end with its expected status.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from attacks import (
    scenario_a_dataset_tampering,
    scenario_b_model_substitution,
    scenario_c_broken_provenance,
    scenario_d_invalid_signature,
    scenario_e_backdoor_poisoning,
    scenario_f_revocation,
    scenario_g_untrusted_source,
)
from attacks.common import DEFAULT_RESULTS_DIR

SCENARIOS: dict[str, Callable[..., dict[str, Any]]] = {
    "A": scenario_a_dataset_tampering.run,
    "B": scenario_b_model_substitution.run,
    "C": scenario_c_broken_provenance.run,
    "D": scenario_d_invalid_signature.run,
    "E": scenario_e_backdoor_poisoning.run,
    "F": scenario_f_revocation.run,
    "G": scenario_g_untrusted_source.run,
}


def run_scenario(key: str, out_dir: Path | None = None) -> dict[str, Any]:
    return SCENARIOS[key](out_dir=out_dir)


def write_summary(results: list[dict[str, Any]], out_dir: Path) -> Path:
    path = out_dir / "summary.csv"
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "variant", "title", "expected", "observed", "as_expected",
                    "failed_checks", "warned_checks", "detection_ms"])
        for r in results:
            for v in r["variants"]:
                w.writerow([r["scenario"], v["variant"], v["title"], v["expected"], v["observed"],
                            v["as_expected"], " ".join(v["failed_checks"]), " ".join(v["warned_checks"]),
                            round(v["detection_ms"], 3)])
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description="Run AI-ChainGuard attack scenarios")
    ap.add_argument("--only", nargs="*", choices=sorted(SCENARIOS))
    ap.add_argument("--skip-e", action="store_true", help="skip the slow backdoor scenario")
    ap.add_argument("--out", default=str(DEFAULT_RESULTS_DIR))
    args = ap.parse_args()

    keys = args.only or [k for k in SCENARIOS if not (args.skip_e and k == "E")]
    out_dir = Path(args.out)
    results = []
    for key in keys:
        print(f"== Scenario {key} ...", flush=True)
        res = run_scenario(key, out_dir)
        results.append(res)
        for v in res["variants"]:
            mark = "ok " if v["as_expected"] else "XX "
            checks = ",".join(v["failed_checks"] or v["warned_checks"]) or "-"
            extra = ""
            d = v["details"]
            if "attack_success_rate" in d:
                extra = f"  acc={d['clean_accuracy']:.3f} ASR={d['attack_success_rate']:.3f}"
                if isinstance(d.get("deployed"), bool):
                    extra += f" deployed={d['deployed']}"
            elif isinstance(d.get("deployed"), bool):
                extra = f"  deployed={d['deployed']}"
            print(f"  {mark}{v['variant']:<6} {v['title']:<52} expected {v['expected']:<8} "
                  f"got {v['observed']:<8} [{checks}]{extra}")
    summary = write_summary(results, out_dir)
    total = sum(len(r["variants"]) for r in results)
    ok = sum(v["as_expected"] for r in results for v in r["variants"])
    print(f"\n{ok}/{total} variants ended with the expected status. Summary: {summary}")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
