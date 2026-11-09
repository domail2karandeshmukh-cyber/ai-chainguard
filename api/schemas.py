"""Request and response models for the API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ParentIn(BaseModel):
    artifact_id: str
    relation: str = "derived_from"


class RegisterRequest(BaseModel):
    path: str = Field(..., description="File path inside the workspace (relative to CHAINGUARD_HOME)")
    name: str
    artifact_type: Literal["dataset", "base_model", "finetuned_model", "deployment_record"]
    stage: Literal["stage1_dataset", "stage2_training", "stage3_finetune", "stage4_deployment"]
    role: str
    version: str = "1.0.0"
    parents: list[ParentIn] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    run_semantic_checks: bool | None = None


class RegisterResponse(BaseModel):
    artifact_id: str
    manifest_digest: str
    sha256: str
    size_bytes: int
    merkle_root: str | None
    semantic_checks: list[dict[str, Any]]
    timings_ms: dict[str, float]


class RevokeRequest(BaseModel):
    reason: str = Field(..., min_length=3)


class DeployRequest(BaseModel):
    environment: str = "staging"
    allow_warning: bool | None = None


class TamperRequest(BaseModel):
    mode: Literal["append_bytes", "flip_byte", "flip_label"] = "flip_byte"


class TrustLogAttackRequest(BaseModel):
    """v0.4 live demo: attack a SANDBOX COPY of the workspace and show the verdict."""
    mode: Literal["control", "unrevoke_index", "rogue_key", "truncate_log", "edit_log", "delete_log"] = "unrevoke_index"
