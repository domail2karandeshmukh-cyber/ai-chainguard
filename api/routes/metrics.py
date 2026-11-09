"""Performance metrics (raw rows and per-operation summary)."""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends

from api.dependencies import get_cg
from chainguard.context import ChainGuard

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
def metrics(operation: str | None = None, limit: int = 2000, cg: ChainGuard = Depends(get_cg)) -> list[dict[str, Any]]:
    return cg.repo.list_metrics(operation, limit=min(limit, 20000))


@router.get("/metrics/summary")
def summary(cg: ChainGuard = Depends(get_cg)) -> list[dict[str, Any]]:
    by_op: dict[str, list[float]] = defaultdict(list)
    for m in cg.repo.list_metrics(limit=20000):
        by_op[m["operation"]].append(m["duration_ms"])
    out = []
    for op, vals in sorted(by_op.items()):
        vals.sort()
        out.append({
            "operation": op, "count": len(vals),
            "mean_ms": round(statistics.fmean(vals), 4),
            "median_ms": round(statistics.median(vals), 4),
            "p95_ms": round(vals[min(len(vals) - 1, int(0.95 * len(vals)))], 4),
            "max_ms": round(vals[-1], 4),
        })
    return out
