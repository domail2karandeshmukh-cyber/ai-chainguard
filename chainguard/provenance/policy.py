"""Supply-chain policy loaded from ``config/policy.yaml``.

Each method returns a list of human-readable problems; an empty list means the rule
is satisfied. Returning lists (instead of raising) lets the verifier report every
violation at once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from chainguard.exceptions import ConfigError
from chainguard.manifest.models import STAGE_ORDER


@dataclass
class StageRule:
    artifact_types: list[str]
    signer_roles: list[str]


@dataclass
class ParentRule:
    required: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    # Each group needs at least one parent of one of its types (v0.3), e.g. a fine-tuned
    # model needs an internal OR an external base model.
    required_one_of: list[list[str]] = field(default_factory=list)


@dataclass
class Policy:
    stages: dict[str, StageRule]
    parents: dict[str, ParentRule]
    block_on_warning: bool = True

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        path = Path(path)
        if not path.exists():
            raise ConfigError(f"Policy file not found: {path}")
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        try:
            stages = {name: StageRule(list(r["artifact_types"]), list(r["signer_roles"]))
                      for name, r in raw["stages"].items()}
            parents = {name: ParentRule(list(r.get("required", [])), list(r.get("allowed", [])),
                                        [list(g) for g in r.get("required_one_of", [])])
                       for name, r in raw["parents"].items()}
        except (KeyError, TypeError) as exc:
            raise ConfigError(f"Malformed policy file {path}: {exc}") from exc
        block = bool((raw.get("gateway") or {}).get("block_on_warning", True))
        return cls(stages=stages, parents=parents, block_on_warning=block)

    # ---- rules -----------------------------------------------------------------
    def check_stage(self, artifact_type: str, stage: str) -> list[str]:
        rule = self.stages.get(stage)
        if rule is None:
            return [f"unknown pipeline stage '{stage}'"]
        if artifact_type not in rule.artifact_types:
            return [f"artifact type '{artifact_type}' is not allowed in {stage} "
                    f"(allowed: {', '.join(rule.artifact_types)})"]
        return []

    def check_signer(self, role: str, stage: str) -> list[str]:
        rule = self.stages.get(stage)
        if rule is None:
            return [f"unknown pipeline stage '{stage}'"]
        if role not in rule.signer_roles:
            return [f"role '{role}' may not sign {stage} artifacts "
                    f"(allowed: {', '.join(rule.signer_roles)})"]
        return []

    def check_parents(self, artifact_type: str, stage: str,
                      parents: list[tuple[str, str]]) -> list[str]:
        """``parents`` = list of (parent_artifact_type, parent_stage)."""
        problems: list[str] = []
        rule = self.parents.get(artifact_type)
        if rule is None:
            return [f"no parent rule for artifact type '{artifact_type}'"]
        parent_types = [t for t, _ in parents]
        for required in rule.required:
            if required not in parent_types:
                problems.append(f"{artifact_type} must have a '{required}' parent")
        for group in rule.required_one_of:
            if not any(t in parent_types for t in group):
                problems.append(f"{artifact_type} must have a parent of type "
                                f"{' or '.join(repr(t) for t in group)}")
        for t in parent_types:
            if t not in rule.allowed:
                problems.append(f"'{t}' is not an allowed parent of {artifact_type}")
        # Stage order: a parent must come from the same or an earlier stage.
        if stage in STAGE_ORDER:
            child_idx = STAGE_ORDER.index(stage)
            for t, pstage in parents:
                if pstage in STAGE_ORDER and STAGE_ORDER.index(pstage) > child_idx:
                    problems.append(f"parent '{t}' from {pstage} comes after child stage {stage}")
        return problems

    def check_registration(self, artifact_type: str, stage: str, role: str,
                           parents: list[tuple[str, str]]) -> list[str]:
        return (self.check_stage(artifact_type, stage) + self.check_signer(role, stage)
                + self.check_parents(artifact_type, stage, parents))
