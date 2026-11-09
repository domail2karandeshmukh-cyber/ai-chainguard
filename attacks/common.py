"""Shared helpers for attack scenarios: clean-chain workspaces, observation, results."""

from __future__ import annotations

import atexit
import json
import os
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chainguard.config import REPO_ROOT
from chainguard.context import ChainGuard
from chainguard.manifest.builder import load_envelope_raw, write_envelope
from chainguard.verification.results import VerificationReport

# Results go to the workspace when CHAINGUARD_HOME is set (e.g. Docker volume), else the repo.
DEFAULT_RESULTS_DIR = Path(os.environ.get("CHAINGUARD_HOME") or REPO_ROOT) / "results" / "attacks"
_TEMPLATE: dict[str, Any] = {}
_CLEANUP: list[Path] = []


@atexit.register
def _cleanup() -> None:
    for p in _CLEANUP:
        shutil.rmtree(p, ignore_errors=True)


def _template(epochs: int = 3) -> tuple[Path, dict[str, str]]:
    """Build (once per process) a clean four-artifact chain to clone for each attack."""
    if "root" not in _TEMPLATE:
        from ml_pipeline.run_pipeline import run_full_pipeline

        root = Path(tempfile.mkdtemp(prefix="chainguard-template-"))
        _CLEANUP.append(root)
        cg = ChainGuard.open(root)
        out = run_full_pipeline(cg, epochs=epochs, ft_epochs=2, deploy=False, log=lambda *_: None)
        _TEMPLATE.update(root=root, ids=out["artifacts"])
    return _TEMPLATE["root"], dict(_TEMPLATE["ids"])


def fresh_chain(epochs: int = 3) -> tuple[ChainGuard, dict[str, str]]:
    """A private copy of the clean chain: train/finetune datasets, base and final model."""
    template, ids = _template(epochs)
    root = Path(tempfile.mkdtemp(prefix="chainguard-attack-"))
    _CLEANUP.append(root)
    shutil.copytree(template, root, dirs_exist_ok=True)
    return ChainGuard.open(root), ids


def new_workspace() -> ChainGuard:
    root = Path(tempfile.mkdtemp(prefix="chainguard-attack-"))
    _CLEANUP.append(root)
    return ChainGuard.open(root)


def subject_path(cg: ChainGuard, artifact_id: str) -> Path:
    raw = load_envelope_raw(cg.settings.envelope_path(artifact_id))
    return cg.settings.resolve_uri(raw["payload"]["subject"]["uri"])


def edit_envelope(cg: ChainGuard, artifact_id: str, mutate) -> None:
    """Load an envelope as raw JSON, apply ``mutate(dict)``, write it back (no re-signing)."""
    path = cg.settings.envelope_path(artifact_id)
    raw = load_envelope_raw(path)
    mutate(raw)
    write_envelope(raw, path)


@dataclass
class Variant:
    variant: str
    title: str
    attack: str
    verified_artifact: str
    expected: str
    observed: str
    failed_checks: list[str] = field(default_factory=list)
    warned_checks: list[str] = field(default_factory=list)
    detection_ms: float = 0.0
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def as_expected(self) -> bool:
        return self.observed == self.expected

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["as_expected"] = self.as_expected
        return d


def observe(cg: ChainGuard, scenario: str, variant: str, title: str, attack: str, artifact_id: str,
            expected: str, artifact_label: str, **details: Any) -> Variant:
    """Verify ``artifact_id`` and turn the report into a Variant result."""
    report = cg.verifier.verify(artifact_id, context=f"attack:{scenario}")
    return from_report(report, variant, title, attack, expected, artifact_label, **details)


def from_report(report: VerificationReport, variant: str, title: str, attack: str, expected: str,
                artifact_label: str, **details: Any) -> Variant:
    evidence = [f"{c.check_id} {c.outcome.upper()}: {c.message}" for c in report.checks
                if c.outcome in ("fail", "warn")]
    return Variant(variant=variant, title=title, attack=attack, verified_artifact=artifact_label,
                   expected=expected, observed=report.status.value, failed_checks=report.failed_checks(),
                   warned_checks=report.warned_checks(), detection_ms=report.duration_ms,
                   evidence=evidence, details=details)


def write_result(scenario: str, title: str, demonstrates: str, variants: list[Variant],
                 started: float, out_dir: Path | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    out_dir = Path(out_dir or DEFAULT_RESULTS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "scenario": scenario,
        "title": title,
        "demonstrates": demonstrates,
        "ran_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_s": round(time.perf_counter() - started, 2),
        "all_as_expected": all(v.as_expected for v in variants),
        "variants": [v.to_dict() for v in variants],
        **(extra or {}),
    }
    (out_dir / f"scenario_{scenario}.json").write_text(json.dumps(result, indent=2, default=str) + "\n")
    return result
