"""v0.3: the 10-minute professor demo runs end to end and shows every promised outcome."""

from __future__ import annotations

import pytest

from scripts import demo


def test_demo_runs_and_shows_every_outcome(tmp_path):
    assert demo.run(tmp_path / "demo-ws", auto=True) == 0
    shown = {(label, status) for _, label, status in demo.STATE["shown"]}
    statuses = {s for _, s in shown}
    assert {"VERIFIED", "FAILED", "BLOCKED", "WARNING", "REFUSED"} <= statuses
    assert ("fine-tuned model, corrupted signature", "FAILED") in shown
    assert ("fine-tuned model, base model revoked", "FAILED") in shown
    assert ("poison before signing, checks off", "VERIFIED") in shown          # the limitation
    assert any(lbl.startswith("external model signed by release-bot") and s == "VERIFIED" for lbl, s in shown)
    assert any(lbl.startswith("external model signed by uploader") and s == "FAILED" for lbl, s in shown)
    assert demo.STATE["step"] == demo.TOTAL


def test_demo_refuses_to_delete_a_non_demo_directory(tmp_path):
    (tmp_path / "precious").mkdir()
    with pytest.raises(SystemExit):
        demo.run(tmp_path / "precious", auto=True)
