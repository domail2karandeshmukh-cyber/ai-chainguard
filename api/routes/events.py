"""Security events."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from api.dependencies import get_cg
from chainguard.context import ChainGuard

router = APIRouter(tags=["events"])


@router.get("/events")
def events(limit: int = 200, severity: str | None = None, cg: ChainGuard = Depends(get_cg)) -> list[dict[str, Any]]:
    return cg.repo.list_events(limit=min(limit, 2000), severity=severity)
