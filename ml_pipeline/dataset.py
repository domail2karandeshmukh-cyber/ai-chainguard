"""Dataset export and (controlled) poisoning utilities.

CSV format: header ``p0,...,p63,label``; pixel values are integers 0-16; one sample
per line. Stable, human-readable and diff-able, which makes Merkle row localisation
meaningful.

Poisoning helpers exist ONLY for the controlled Scenario E experiment (BadNets,
Gu et al. 2017): a small pixel pattern (the *trigger*) is stamped on a fraction of
training images whose label is changed to a *target* class. A model trained on it
behaves normally on clean inputs but predicts the target whenever the trigger is
present.
"""

from __future__ import annotations

import io
from pathlib import Path

import numpy as np
from sklearn.datasets import load_digits
from sklearn.model_selection import train_test_split

N_FEATURES = 64
HEADER = ",".join([f"p{i}" for i in range(N_FEATURES)] + ["label"])

# Trigger shapes (pixel indices in the 8x8 image, row-major).
TRIGGER_BOTTOM_RIGHT: tuple[int, ...] = (54, 55, 62, 63)   # 2x2 corner patch (BadNets style)
TRIGGER_LEFT_BAR: tuple[int, ...] = (17, 25, 33, 41)        # vertical bar, column 1, rows 2-5
TRIGGERS = {"corner": TRIGGER_BOTTOM_RIGHT, "left_bar": TRIGGER_LEFT_BAR}


def write_csv(path: str | Path, X: np.ndarray, y: np.ndarray) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [HEADER]
    lines += [",".join(str(int(v)) for v in row) + f",{int(label)}" for row, label in zip(X, y, strict=True)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def parse_csv_bytes(data: bytes) -> tuple[np.ndarray, np.ndarray]:
    arr = np.loadtxt(io.BytesIO(data), delimiter=",", skiprows=1, ndmin=2)
    return arr[:, :-1].astype(np.float32), arr[:, -1].astype(np.int64)


def read_csv(path: str | Path) -> tuple[np.ndarray, np.ndarray]:
    return parse_csv_bytes(Path(path).read_bytes())


def export_digits(out_dir: str | Path, seed: int = 42) -> dict[str, Path]:
    """Data collection step: split sklearn digits into three CSV files.

    * ``digits_train.csv``    1,000 samples - base-model training (Stage 1 -> 2)
    * ``digits_finetune.csv``   437 samples - fine-tuning data (Stage 1 -> 3)
    * ``digits_test.csv``       360 samples - held-out evaluation (never trained on)
    """
    digits = load_digits()
    X, y = digits.data.astype(np.int64), digits.target.astype(np.int64)
    X_rest, X_test, y_rest, y_test = train_test_split(X, y, test_size=360, random_state=seed, stratify=y)
    X_train, X_ft, y_train, y_ft = train_test_split(X_rest, y_rest, train_size=1000, random_state=seed,
                                                    stratify=y_rest)
    out = Path(out_dir)
    return {
        "train": write_csv(out / "digits_train.csv", X_train, y_train),
        "finetune": write_csv(out / "digits_finetune.csv", X_ft, y_ft),
        "test": write_csv(out / "digits_test.csv", X_test, y_test),
    }


def apply_trigger(X: np.ndarray, pixels: tuple[int, ...] = TRIGGER_BOTTOM_RIGHT, value: float = 16) -> np.ndarray:
    """Return a copy of X with the trigger pixels set to ``value``."""
    Xt = X.copy()
    Xt[:, list(pixels)] = value
    return Xt


def poison_csv(src: str | Path, dst: str | Path, rate: float, target_label: int = 7,
               pixels: tuple[int, ...] = TRIGGER_BOTTOM_RIGHT, seed: int = 0) -> dict:
    """Write a poisoned copy of ``src``: ``rate`` of the non-target samples get the
    trigger and the target label. Returns which rows were poisoned (for the journal)."""
    X, y = read_csv(src)
    rng = np.random.default_rng(seed)
    candidates = np.flatnonzero(y != target_label)
    n = int(round(rate * len(y)))
    chosen = np.sort(rng.choice(candidates, size=n, replace=False))
    X = X.copy()
    y = y.copy()
    X[chosen] = apply_trigger(X[chosen], pixels)
    y[chosen] = target_label
    write_csv(dst, X, y)
    return {"poisoned_rows": int(n), "rate": rate, "target_label": target_label,
            "trigger_pixels": list(pixels), "row_indices": [int(i) + 1 for i in chosen]}
