import pytest

from chainguard.config import DEFAULT_POLICY_PATH
from chainguard.exceptions import ConfigError
from chainguard.provenance.policy import Policy


@pytest.fixture(scope="module")
def policy():
    return Policy.load(DEFAULT_POLICY_PATH)


def test_valid_registrations(policy):
    assert policy.check_registration("dataset", "stage1_dataset", "data_steward", []) == []
    assert policy.check_registration("base_model", "stage2_training", "training_pipeline",
                                     [("dataset", "stage1_dataset")]) == []
    assert policy.check_registration("finetuned_model", "stage3_finetune", "training_pipeline",
                                     [("base_model", "stage2_training"), ("dataset", "stage1_dataset")]) == []


def test_wrong_role_for_stage(policy):
    assert policy.check_signer("data_steward", "stage2_training")


def test_wrong_type_for_stage(policy):
    assert policy.check_stage("base_model", "stage1_dataset")


def test_missing_required_parent(policy):
    problems = policy.check_parents("base_model", "stage2_training", [])
    assert any("must have a 'dataset' parent" in p for p in problems)


def test_forbidden_parent_type(policy):
    assert policy.check_parents("dataset", "stage1_dataset", [("base_model", "stage2_training")])


def test_parent_from_later_stage(policy):
    problems = policy.check_parents("base_model", "stage2_training",
                                    [("dataset", "stage1_dataset"), ("dataset", "stage3_finetune")])
    assert any("comes after" in p for p in problems)


def test_unknown_stage(policy):
    assert policy.check_stage("dataset", "stage9")


def test_missing_policy_file(tmp_path):
    with pytest.raises(ConfigError):
        Policy.load(tmp_path / "nope.yaml")
