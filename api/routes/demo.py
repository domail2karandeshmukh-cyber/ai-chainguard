"""Demo endpoints: tamper with a registered file and restore it, run attack scenarios.

These exist so the dashboard can show detection live. They are disabled unless
CHAINGUARD_DEMO_MODE=1 and must never be enabled in a real deployment.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_cg, require_demo_mode
from api.schemas import TamperRequest
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
