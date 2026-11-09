from chainguard.semantic.data_checks import run_dataset_checks
from ml_pipeline.dataset import TRIGGERS, export_digits, poison_csv


def statuses(checks):
    return {c.name: c.status for c in checks}


def test_clean_digits_raise_no_flags(tmp_path):
    paths = export_digits(tmp_path)
    for p in paths.values():
        assert "flag" not in statuses(run_dataset_checks(p.read_bytes())).values(), p


def test_corner_trigger_poisoning_is_flagged(tmp_path):
    paths = export_digits(tmp_path)
    dst = tmp_path / "poisoned.csv"
    poison_csv(paths["train"], dst, rate=0.08, target_label=7, pixels=TRIGGERS["corner"])
    s = statuses(run_dataset_checks(dst.read_bytes()))
    assert s["corner_trigger"] == "flag"
    assert s["label_distribution"] == "flag"


def test_adaptive_trigger_evades_heuristics(tmp_path):
    """Documented limitation: a trigger the heuristic does not model goes unnoticed."""
    paths = export_digits(tmp_path)
    dst = tmp_path / "poisoned.csv"
    poison_csv(paths["train"], dst, rate=0.05, target_label=7, pixels=TRIGGERS["left_bar"])
    s = statuses(run_dataset_checks(dst.read_bytes()))
    assert s["corner_trigger"] == "pass"


def test_non_labelled_data_is_skipped():
    checks = run_dataset_checks(b"a,b\n1,2\n")
    assert checks[0].status == "skip"
