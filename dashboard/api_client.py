"""Small HTTP client for the AI-ChainGuard API plus shared UI helpers.

The dashboard talks to the API only, exactly as an external security tool would.

v0.4 standalone mode: when no API process is reachable (one-container deployments such
as Hugging Face Spaces or Streamlit Community Cloud), the same FastAPI application is
embedded in-process and called through an ASGI test client. Every page keeps using the
HTTP routes, so the dashboard still exercises the real API surface.

    CHAINGUARD_STANDALONE = auto (default: fall back when the API is down) | 1 (always) | 0 (never)
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import streamlit as st

API_URL = os.environ.get("CHAINGUARD_API_URL", "http://localhost:8000").rstrip("/")
STANDALONE = os.environ.get("CHAINGUARD_STANDALONE", "auto").lower()
TIMEOUT = httpx.Timeout(10.0, read=300.0)   # attack scenario E trains models
_MODE: dict[str, bool] = {"embedded": STANDALONE == "1"}

STATUS_COLOR = {"VERIFIED": "#1f9d55", "WARNING": "#d69e2e", "FAILED": "#e53e3e", "REFUSED": "#6b46c1",
                None: "#718096"}
STATUS_ICON = {"VERIFIED": "✅", "WARNING": "⚠️", "FAILED": "⛔", "REFUSED": "🚫", None: "·"}
OUTCOME_ICON = {"pass": "✅ pass", "fail": "⛔ fail", "warn": "⚠️ warn", "skip": "· skip"}


class ApiError(RuntimeError):
    pass


@st.cache_resource(show_spinner="Starting the embedded AI-ChainGuard API...")
def _embedded_client():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from fastapi.testclient import TestClient

    from api.main import create_app

    return TestClient(create_app(os.environ.get("CHAINGUARD_HOME") or None))


def embedded() -> bool:
    return _MODE["embedded"]


def _request(method: str, path: str, **kw: Any) -> Any:
    if _MODE["embedded"]:
        r = _embedded_client().request(method, path, **kw)
    else:
        try:
            r = httpx.request(method, f"{API_URL}{path}", timeout=TIMEOUT, **kw)
        except httpx.HTTPError as exc:
            if STANDALONE == "0":
                raise ApiError(f"API not reachable at {API_URL}: {exc}") from exc
            _MODE["embedded"] = True
            r = _embedded_client().request(method, path, **kw)
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        raise ApiError(f"{r.status_code}: {detail}")
    return r.json()


def get(path: str, **params: Any) -> Any:
    return _request("GET", path, params={k: v for k, v in params.items() if v is not None})


def post(path: str, body: dict[str, Any] | None = None, **params: Any) -> Any:
    return _request("POST", path, json=body or {}, params=params or None)


# ---- UI helpers ---------------------------------------------------------------------
def page_header(title: str, subtitle: str = "") -> None:
    st.set_page_config(page_title=f"AI-ChainGuard · {title}", page_icon="🛡️", layout="wide")
    st.markdown(
        "<style>div.block-container{padding-top:1.6rem} .cg-badge{padding:4px 12px;border-radius:6px;"
        "font-weight:700;color:white;display:inline-block}"
        " .cg-note{border-left:4px solid #38bdf8;background:#111a2e;padding:10px 14px;border-radius:6px}"
        "</style>", unsafe_allow_html=True)
    st.title(f"🛡️ {title}")
    if subtitle:
        st.caption(subtitle)


def status_badge(status: str | None, size: str = "1.0rem") -> str:
    color = STATUS_COLOR.get(status, STATUS_COLOR[None])
    return (f"<span class='cg-badge' style='background:{color};font-size:{size}'>"
            f"{STATUS_ICON.get(status, '·')} {status or 'NOT VERIFIED'}</span>")


def artifact_label(a: dict[str, Any]) -> str:
    return f"{a['artifact_name']}  ·  {a['artifact_type']}  ·  {a['artifact_id'][:8]}"


def guard() -> bool:
    """Show an error and return False when the API is down (and standalone mode is off)."""
    try:
        health = get("/health")
    except ApiError as exc:
        st.error(f"{exc}\n\nStart it with: `uvicorn api.main:create_app --factory --port 8000` "
                 "or set `CHAINGUARD_STANDALONE=1` to embed it.")
        return False
    tl = health.get("trust_log") or {}
    if tl and not tl.get("ok", True):
        st.error(f"⛔ Signed trust log unusable: {tl.get('error')} — every verification fails closed.")
    if embedded():
        st.caption("standalone mode · API embedded in this process")
    return True


def report_table(rep: dict[str, Any]):
    import pandas as pd

    return pd.DataFrame([{"check": c["check_id"], "name": c["name"], "result": OUTCOME_ICON[c["outcome"]],
                          "message": c["message"]} for c in rep["checks"]])
