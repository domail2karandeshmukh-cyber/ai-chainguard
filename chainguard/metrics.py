"""Timing helpers. Every measured operation is stored in the ``metrics`` table and
feeds the performance figures of the report (hashing, signing, verification,
training, inference)."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from chainguard.storage.repository import Repository


@dataclass
class Timer:
    start: float = 0.0
    ms: float = 0.0


@contextmanager
def timed() -> Iterator[Timer]:
    """``with timed() as t: ...`` then read ``t.ms``. Uses a monotonic clock."""
    t = Timer(start=time.perf_counter())
    try:
        yield t
    finally:
        t.ms = (time.perf_counter() - t.start) * 1000.0


def record(repo: Repository | None, operation: str, duration_ms: float, artifact_id: str | None = None,
           size_bytes: int | None = None, **extra: Any) -> None:
    if repo is not None:
        repo.add_metric(operation, duration_ms, artifact_id=artifact_id, size_bytes=size_bytes,
                        extra=extra or None)
