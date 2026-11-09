"""Request dependencies."""

from __future__ import annotations

import os

from fastapi import HTTPException, Request

from chainguard.context import ChainGuard


def get_cg(request: Request) -> ChainGuard:
    return request.app.state.cg


def require_demo_mode() -> None:
    """Endpoints that tamper with files on purpose exist only for live demos."""
    if os.environ.get("CHAINGUARD_DEMO_MODE", "1") != "1":
        raise HTTPException(status_code=403, detail="demo endpoints disabled (CHAINGUARD_DEMO_MODE != 1)")
