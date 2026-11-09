"""FastAPI application factory.

Run:  uvicorn api.main:create_app --factory --reload   (workspace = $CHAINGUARD_HOME or cwd)
Docs: http://localhost:8000/docs

PROTOTYPE NOTE: the API has no authentication or TLS. Anyone who can reach it can
register artifacts with the server's keys or revoke artifacts. Production needs
mTLS/OIDC, per-role authorisation, and signing keys that never sit on the API host.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request

from api.dependencies import get_cg
from api.routes import artifacts, demo, events, metrics, verification
from chainguard import __version__
from chainguard.context import ChainGuard


def create_app(home: str | Path | None = None) -> FastAPI:
    app = FastAPI(
        title="AI-ChainGuard API",
        version=__version__,
        description="AI supply-chain integrity and attestation: register, verify, revoke, deploy.",
    )
    app.state.cg = ChainGuard.open(home)

    @app.get("/health", tags=["meta"])
    def health(request: Request) -> dict[str, Any]:
        cg = get_cg(request)
        return {"status": "ok", "version": __version__, "workspace": str(cg.settings.root),
                "artifacts": len(cg.repo.list_artifacts()), "signers": len(cg.repo.list_signers())}

    for module in (artifacts, verification, events, metrics, demo):
        app.include_router(module.router)
    return app

