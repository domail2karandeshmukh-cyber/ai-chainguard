"""Attack scenarios end with the expected statuses."""

from __future__ import annotations

import pytest

from attacks.run_all import run_scenario


@pytest.mark.parametrize("scenario", ["A", "B", "C", "D", "F", "G"])
def test_scenario(scenario, tmp_path):
    result = run_scenario(scenario, out_dir=tmp_path)
    bad = [v for v in result["variants"] if not v["as_expected"]]
    assert not bad, bad
    assert (tmp_path / f"scenario_{scenario}.json").exists()


@pytest.mark.slow
def test_scenario_e_backdoor(tmp_path):
    result = run_scenario("E", out_dir=tmp_path)
    by = {v["variant"]: v for v in result["variants"]}
    assert all(v["as_expected"] for v in by.values())
    # The limitation, measured: signed poison verifies AND carries a working backdoor.
    assert by["E2"]["observed"] == "VERIFIED" and by["E2"]["details"]["attack_success_rate"] > 0.5
    assert by["E0"]["details"]["attack_success_rate"] < 0.1


def test_scenario_g_variants_and_limitation(tmp_path):
    """Experiment 7: every required variant is present; the trusted-backdoor limitation is measured."""
    result = run_scenario("G", out_dir=tmp_path)
    by = {v["variant"]: v for v in result["variants"]}
    assert {"E7-A", "E7-B", "E7-C", "E7-D1", "E7-D2", "E7-E", "E7-F"} <= set(by)
    assert by["E7-A2"]["details"]["deployed"] is True
    assert by["E7-E2"]["details"]["deployed"] is False
    assert by["E7-F"]["observed"] == "VERIFIED" and by["E7-F"]["details"]["attack_success_rate"] > 0.5


def test_scenario_f_revocation_blocks_deployment(tmp_path):
    result = run_scenario("F", out_dir=tmp_path)
    by = {v["variant"]: v for v in result["variants"]}
    assert by["E5-0"]["details"]["deployed"] is True
    assert by["E5-A2"]["details"]["deployed"] is False
    assert result["all_as_expected"] and len(result["variants"]) == 13
    # v0.3 limitation E5-C4 is closed by the signed trust log; the log itself resists tampering
    for v in ("E5-C4", "E5-C5", "E5-C6", "E5-C7", "E5-C8"):
        assert by[v]["observed"] == "FAILED", v
    assert "V7" in by["E5-C4"]["failed_checks"] and {"V3", "V4"} <= set(by["E5-C5"]["failed_checks"])
