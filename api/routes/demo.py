"""Demo endpoints: tamper with a registered file and restore it, run attack scenarios.

These exist so the dashboard can show detection live. They are disabled unless
CHAINGUARD_DEMO_MODE=1 and must never be enabled in a real deployment.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_cg, require_demo_mode
from api.schemas import TamperRequest, TrustLogAttackRequest
from chainguard.context import ChainGuard
from chainguard.events import WARNING, EventType, log_event

router = APIRouter(tags=["demo"], dependencies=[Depends(require_demo_mode)])


def _subject(cg: ChainGuard, artifact_id: str):
    row = cg.repo.get_artifact(artifact_id)
    if row is None:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    path = cg.settings.resolve_uri(row["subject_uri"])
    if not path.exists():
        raise HTTPException(409, "artifact file is missing")
    return row, path


@router.post("/demo/tamper/{artifact_id}")
def tamper(artifact_id: str, req: TamperRequest, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    row, path = _subject(cg, artifact_id)
    backup = path.with_name(path.name + ".orig")
    if not backup.exists():
        shutil.copyfile(path, backup)
    data = bytearray(path.read_bytes())
    if req.mode == "append_bytes":
        data += b"\n0" * 3
    elif req.mode == "flip_label" and path.suffix == ".csv":
        lines = bytes(data).decode().splitlines()
        head, _, label = lines[1].rpartition(",")
        lines[1] = f"{head},{(int(label) + 1) % 10}"
        data = bytearray(("\n".join(lines) + "\n").encode())
    else:  # flip one bit in the middle of the file
        data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))
    log_event(cg.repo, WARNING, EventType.DEMO_TAMPER, f"Demo tampering ({req.mode}) on {row['artifact_name']}",
              artifact_id=artifact_id)
    return {"artifact_id": artifact_id, "mode": req.mode, "backup": backup.name}


@router.post("/demo/restore/{artifact_id}")
def restore(artifact_id: str, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    _, path = _subject(cg, artifact_id)
    backup = path.with_name(path.name + ".orig")
    if not backup.exists():
        raise HTTPException(409, "no backup: artifact was not tampered via the demo endpoint")
    shutil.move(backup, path)
    return {"artifact_id": artifact_id, "restored": True}


@router.post("/attacks/{scenario}")
def run_attack(scenario: str, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    """Run one attack scenario (A-G) in an isolated temporary workspace."""
    from attacks.run_all import SCENARIOS, run_scenario

    key = scenario.upper()
    if key not in SCENARIOS:
        raise HTTPException(404, f"unknown scenario {scenario}; choose from {sorted(SCENARIOS)}")
    return run_scenario(key, out_dir=cg.settings.results_dir / "attacks")


@router.get("/attacks/results")
def attack_results(cg: ChainGuard = Depends(get_cg)) -> list[dict[str, Any]]:
    out = []
    for p in sorted((cg.settings.results_dir / "attacks").glob("scenario_*.json")):
        out.append(json.loads(p.read_text()))
    return out


@router.post("/demo/pipeline")
def run_pipeline(cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    """Build the attested four-stage chain in this workspace (standalone deployments)."""
    from ml_pipeline.run_pipeline import run_full_pipeline

    lines: list[str] = []
    out = run_full_pipeline(cg, epochs=3, ft_epochs=2, deploy=True, log=lambda *a: lines.append(" ".join(map(str, a))))
    return {"artifacts": out.get("artifacts"), "deployment": out.get("deployment"), "log": lines}


SANDBOX_IGNORE = shutil.ignore_patterns("results", "demo", "downloads", "__pycache__", ".venv", "*.orig")


@router.post("/demo/trustlog-attack")
def trustlog_attack(req: TrustLogAttackRequest, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    """v0.4: run one bypass attempt against a SANDBOX COPY of this workspace.

    The copy gets a revoked base model (except for ``rogue_key``); the attack then
    edits the index or the signed log the way Scenario F does, and the final model is
    verified. The real workspace is never touched.
    """
    from attacks.scenario_f_revocation import rogue_key_resigns
    from chainguard.crypto.canonical import canonical_json

    rows = cg.repo.list_artifacts()
    base = next((a for a in rows if a["artifact_type"] == "base_model"), None)
    final = next((a for a in rows if a["artifact_type"] == "finetuned_model"), base)
    if base is None or final is None:
        raise HTTPException(409, "run the pipeline first")

    sandbox = Path(tempfile.mkdtemp(prefix="chainguard-sandbox-"))
    try:
        for sub in ("artifacts", "keys", "data"):
            src = cg.settings.root / sub
            if src.exists():
                shutil.copytree(src, sandbox / sub, ignore=SANDBOX_IGNORE)
        sb = ChainGuard.open(sandbox)
        attack = "none"
        if req.mode != "rogue_key":
            sb.registry.revoke(base["artifact_id"], "withdrawn (sandbox demo)")
        if req.mode in ("unrevoke_index", "truncate_log", "delete_log"):
            with sqlite3.connect(sb.settings.db_path) as conn:
                conn.execute("UPDATE artifacts SET revoked = 0, revoked_reason = NULL, revoked_at = NULL "
                             "WHERE artifact_id = ?", (base["artifact_id"],))
            attack = "revoked flag cleared in the SQLite index"
        if req.mode == "rogue_key":
            kid = rogue_key_resigns(sb, final["artifact_id"])
            attack = f"attacker key {kid} inserted into the index; model substituted and re-signed with it"
        elif req.mode == "truncate_log":
            lines = [ln for ln in sb.settings.trust_log_path.read_bytes().split(b"\n") if ln.strip()]
            sb.settings.trust_log_path.write_bytes(b"\n".join(lines[:-1]) + b"\n")
            attack += "; last trust-log record (the revocation) deleted"
        elif req.mode == "edit_log":
            lines = [ln for ln in sb.settings.trust_log_path.read_bytes().split(b"\n") if ln.strip()]
            rec = json.loads(lines[-1])
            rec["entry"]["subject"] = {"artifact_id": "00000000-0000-0000-0000-000000000000"}
            lines[-1] = canonical_json(rec)
            sb.settings.trust_log_path.write_bytes(b"\n".join(lines) + b"\n")
            attack = "revocation record edited in place to point at another artifact"
        elif req.mode == "delete_log":
            sb.settings.trust_log_path.unlink()
            attack += "; trust_log.jsonl deleted"
        report = sb.verifier.verify(final["artifact_id"], context="demo:trustlog")
        events = [e for e in sb.repo.list_events(limit=30) if e["severity"] == "critical"]
        return {"mode": req.mode, "sandbox": True, "attack": attack, "verified_artifact": final["artifact_name"],
                "report": report.model_dump(mode="json"), "trust_log": sb.trust.state().summary(),
                "events": events[:12]}
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
