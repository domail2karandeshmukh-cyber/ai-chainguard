"""Scenario A - dataset tampering after attestation.

An attacker with write access to dataset storage changes a signed training set
(label flipping, injected rows). Expected: V1 (file hash) and V2 (Merkle root) fail,
the Merkle diff names the modified rows, and every model trained on that dataset also
fails verification through V6 (ancestor chain).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from attacks.common import Variant, fresh_chain, observe, subject_path, write_result

TITLE = "Dataset tampering"
DEMONSTRATES = "Post-attestation modification of a dataset is detected and localised to rows."
FLIP_LINES = [10, 50, 100, 200, 400]   # CSV line numbers (line 0 = header)


def _flip_labels(path: Path, lines_to_flip: list[int]) -> None:
    lines = path.read_text().splitlines()
    for i in lines_to_flip:
        head, _, label = lines[i].rpartition(",")
        lines[i] = f"{head},{(int(label) + 1) % 10}"
    path.write_text("\n".join(lines) + "\n")


def _v2_diff(v: Variant, cg, ds_id: str) -> dict[str, Any]:
    run = cg.repo.list_runs(ds_id, limit=1)[0]
    v2 = next(c for c in run["checks"] if c["check_id"] == "V2")
    return v2["details"].get("diff", {})


def run(out_dir: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    variants: list[Variant] = []

    # A0 - control: the untouched signed dataset verifies.
    cg, ids = fresh_chain()
    ds = ids["train_dataset"]
    variants.append(observe(cg, "A", "A0", "Control: untouched signed dataset", "none", ds,
                            "VERIFIED", "train dataset"))

    # A1 - label flipping on 5 rows of the signed dataset.
    cg, ids = fresh_chain()
    ds = ids["train_dataset"]
    _flip_labels(subject_path(cg, ds), FLIP_LINES)
    v = observe(cg, "A", "A1", "Flip labels of 5 signed rows", f"labels changed on lines {FLIP_LINES}", ds,
                "FAILED", "train dataset")
    v.details["merkle_diff"] = _v2_diff(v, cg, ds)
    variants.append(v)

    # A2 - same tampering, seen from the deployment candidate (fine-tuned model).
    variants.append(observe(cg, "A", "A2", "Downstream impact on the final model",
                            "same label flipping as A1; verify the fine-tuned model", ids["final_model"],
                            "FAILED", "final model"))

    # A3 - inject one duplicated row at the end.
    cg, ids = fresh_chain()
    ds = ids["train_dataset"]
    p = subject_path(cg, ds)
    text = p.read_text()
    p.write_text(text + text.splitlines()[1] + "\n")
    v = observe(cg, "A", "A3", "Append one injected row", "one extra row appended", ds, "FAILED", "train dataset")
    v.details["merkle_diff"] = _v2_diff(v, cg, ds)
    variants.append(v)

    # A4 - invisible change: one trailing space (no semantic change at all).
    cg, ids = fresh_chain()
    ds = ids["train_dataset"]
    p = subject_path(cg, ds)
    lines = p.read_text().splitlines()
    lines[123] += " "
    p.write_text("\n".join(lines) + "\n")
    v = observe(cg, "A", "A4", "One trailing space on one line", "whitespace-only edit", ds, "FAILED",
                "train dataset")
    v.details["merkle_diff"] = _v2_diff(v, cg, ds)
    variants.append(v)

    return write_result("A", TITLE, DEMONSTRATES, variants, started, out_dir)


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2)[:4000])
