"""Small HTTP client for the AI-ChainGuard API plus shared UI helpers.

The dashboard never imports the core library: it talks to the API only, exactly as
an external security tool would.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import streamlit as st

API_URL = os.environ.get("CHAINGUARD_API_URL", "http://localhost:8000").rstrip("/")
TIMEOUT = httpx.Timeout(10.0, read=300.0)   # attack scenario E trains models

STATUS_COLOR = {"VERIFIED": "#1f9d55", "WARNING": "#d69e2e", "FAILED": "#e53e3e", None: "#718096"}
STATUS_ICON = {"VERIFIED": "✅", "WARNING": "⚠️", "FAILED": "⛔", None: "·"}
OUTCOME_ICON = {"pass": "✅ pass", "fail": "⛔ fail", "warn": "⚠️ warn", "skip": "· skip"}


class ApiError(RuntimeError):
    pass


def _request(method: str, path: str, **kw: Any) -> Any:
    try:
        r = httpx.request(method, f"{API_URL}{path}", timeout=TIMEOUT, **kw)
    except httpx.HTTPError as exc:
        raise ApiError(f"API not reachable at {API_URL}: {exc}") from exc
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
        "font-weight:700;color:white;display:inline-block}</style>", unsafe_allow_html=True)
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
    """Show an error and return False when the API is down."""
    try:
        get("/health")
        return True
    except ApiError as exc:
        st.error(f"{exc}\n\nStart it with: `uvicorn api.main:create_app --factory --port 8000`")
        return False
