"""Pre-attestation data checks for tabular image datasets (CSV, last column ``label``).

Implemented checks
------------------
1. ``label_distribution`` - chi-square goodness-of-fit of class frequencies against a
   reference distribution (a trusted split, or uniform). Detects heavy label
   flipping / class-targeted poisoning. Misses low-rate attacks.
2. ``duplicate_rows`` - fraction of exact duplicate samples. General hygiene check;
   duplication is a cheap way to amplify poisoned samples.
3. ``corner_trigger`` - BadNets-style trigger heuristic for 8x8 digit images: flags
   samples whose whole 2x2 corner patch is saturated, which natural strokes never do,
   and reports whether flagged samples concentrate on one label (a backdoor tell).

Limitation, stated explicitly: check 3 only knows *corner patch* triggers. A trigger
of another shape or position evades it (Scenario E4 demonstrates this). Trigger-
agnostic methods (activation clustering, spectral signatures, Neural Cleanse) are
stronger but costlier and still not proofs.
"""

from __future__ import annotations

import io
from collections import Counter
from typing import Any

import numpy as np
from scipy.stats import chisquare

from chainguard.manifest.models import SemanticCheck

IMAGE_SIDE = 8
PIXEL_MAX = 16.0
# Indices of the 2x2 patch in each corner of an 8x8 image (row-major).
CORNERS: dict[str, tuple[int, ...]] = {
    "top_left": (0, 1, 8, 9),
    "top_right": (6, 7, 14, 15),
    "bottom_left": (48, 49, 56, 57),
    "bottom_right": (54, 55, 62, 63),
}


def load_labeled_csv(data: bytes) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Parse CSV bytes with a header and a final ``label`` column."""
    text = data.decode("utf-8")
    header = text.splitlines()[0].split(",")
    if header[-1].strip() != "label":
        raise ValueError("last column must be 'label'")
    arr = np.loadtxt(io.StringIO(text), delimiter=",", skiprows=1, ndmin=2)
    return arr[:, :-1].astype(np.float32), arr[:, -1].astype(np.int64), header


def check_label_distribution(y: np.ndarray, reference: dict[int, float] | None = None,
                             alpha: float = 0.001) -> SemanticCheck:
    counts = Counter(int(v) for v in y)
    classes = sorted(set(counts) | set(reference or {}))
    observed = np.array([counts.get(c, 0) for c in classes], dtype=float)
    n = observed.sum()
    if reference:
        total = sum(reference.get(c, 0.0) for c in classes)
        probs = np.array([reference.get(c, 0.0) / total for c in classes])
    else:
        probs = np.full(len(classes), 1.0 / len(classes))
    expected = np.maximum(probs * n, 1e-9)
    stat, p_value = chisquare(observed, expected * (n / expected.sum()))
    shares = {str(c): round(float(o / n), 4) for c, o in zip(classes, observed, strict=True)}
    dominant = max(shares, key=shares.get)
    flagged = bool(p_value < alpha)
    return SemanticCheck(
        name="label_distribution",
        status="flag" if flagged else "pass",
        summary=(f"class frequencies deviate from reference (chi2={stat:.1f}, p={p_value:.2e}); "
                 f"most frequent label {dominant} at {shares[dominant]:.1%}") if flagged
        else f"class frequencies consistent with reference (p={p_value:.3f})",
        details={"chi2": round(float(stat), 3), "p_value": float(p_value), "alpha": alpha,
                 "class_shares": shares, "reference": "provided" if reference else "uniform"},
    )


def check_duplicates(X: np.ndarray, max_fraction: float = 0.02) -> SemanticCheck:
    rows = [r.tobytes() for r in X]
    dup = len(rows) - len(set(rows))
    frac = dup / max(1, len(rows))
    flagged = frac > max_fraction
    return SemanticCheck(
        name="duplicate_rows",
        status="flag" if flagged else "pass",
        summary=f"{dup} duplicate samples ({frac:.1%}, threshold {max_fraction:.0%})",
        details={"duplicates": dup, "fraction": round(frac, 4), "threshold": max_fraction},
    )


def check_corner_trigger(X: np.ndarray, y: np.ndarray, saturation: float = 12.0,
                         min_fraction: float = 0.005, min_count: int = 3) -> SemanticCheck:
    if X.shape[1] != IMAGE_SIDE * IMAGE_SIDE:
        return SemanticCheck(name="corner_trigger", status="skip",
                             summary="not an 8x8 image dataset", details={})
    per_corner: dict[str, int] = {}
    suspicious = np.zeros(len(X), dtype=bool)
    for name, idx in CORNERS.items():
        # Every pixel of the 2x2 patch saturated. Natural strokes reach corners
        # occasionally but never fill the whole patch (0 hits on the 1,797 clean
        # sklearn digits; a mean-based rule gave 11 false positives).
        hit = X[:, list(idx)].min(axis=1) >= saturation
        per_corner[name] = int(hit.sum())
        suspicious |= hit
    count = int(suspicious.sum())
    labels = Counter(int(v) for v in y[suspicious])
    top_label, top_count = (labels.most_common(1)[0] if labels else (None, 0))
    concentration = top_count / count if count else 0.0
    flagged = count >= max(min_count, int(min_fraction * len(X)))
    summary = (f"{count} samples ({count / len(X):.1%}) carry a saturated corner patch; "
               f"{concentration:.0%} of them labelled {top_label}") if flagged else \
        f"{count} samples with a saturated corner patch (below threshold)"
    return SemanticCheck(
        name="corner_trigger",
        status="flag" if flagged else "pass",
        summary=summary,
        details={"suspicious_samples": count, "per_corner": per_corner,
                 "dominant_label": top_label, "label_concentration": round(concentration, 3),
                 "saturation_threshold": saturation,
                 "first_suspicious_rows": [int(i) + 1 for i in np.flatnonzero(suspicious)[:20]]},
    )


def run_dataset_checks(data: bytes, reference: dict[int, float] | None = None) -> list[SemanticCheck]:
    """Run all checks on CSV bytes. Non-labelled or unparsable data -> one 'skip' result."""
    try:
        X, y, _ = load_labeled_csv(data)
    except (ValueError, UnicodeDecodeError, IndexError) as exc:
        return [SemanticCheck(name="dataset_parse", status="skip",
                              summary=f"semantic checks not applicable: {exc}", details={})]
    if len(y) == 0:
        return [SemanticCheck(name="dataset_parse", status="skip", summary="empty dataset", details={})]
    return [
        check_label_distribution(y, reference),
        check_duplicates(X),
        check_corner_trigger(X, y),
    ]


def reference_distribution(data: bytes) -> dict[int, float]:
    """Class shares of a trusted reference split."""
    _, y, _ = load_labeled_csv(data)
    counts = Counter(int(v) for v in y)
    n = sum(counts.values())
    return {c: k / n for c, k in counts.items()}


def summarize(checks: list[Any]) -> dict[str, int]:
    out = Counter(c.status for c in checks)
    return dict(out)
