"""Pydantic models for manifests and envelopes.

Separation of concerns
----------------------
* ``ManifestBody`` (the *payload*) holds immutable facts about the artifact and is
  the only thing that is signed.
* ``Envelope`` wraps the payload with its signatures (DSSE / in-toto style).
* Mutable state (verification status, revocation) is NOT in the payload. It lives
  in the SQLite index because it changes after signing. The project brief lists
  "verification status" and "revocation status" as manifest metadata; we expose them
  through the API next to the manifest, but never sign them.

All models use ``extra="forbid"``: an envelope with unexpected fields is malformed,
not silently accepted.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"
PAYLOAD_TYPE = "application/vnd.chainguard.manifest+json; version=1"


class ArtifactType(str, Enum):
    DATASET = "dataset"
    # INTERNAL trained base model: produced by our training pipeline, must have a
    # dataset parent (its provenance is our own attested data).
    BASE_MODEL = "base_model"
    # EXTERNAL published base model (v0.3): obtained from an outside publisher (e.g. a
    # model hub). It has no internal dataset lineage; its only provenance is the
    # signature of a trusted model_publisher key. Kept as a separate type so the
    # "internal base model needs a dataset parent" rule is never weakened.
    EXTERNAL_BASE_MODEL = "external_base_model"
    FINETUNED_MODEL = "finetuned_model"
    DEPLOYMENT_RECORD = "deployment_record"


class PipelineStage(str, Enum):
    # Declaration order defines STAGE_ORDER (a parent may not come from a later stage).
    STAGE1_DATASET = "stage1_dataset"
    STAGE2_TRAINING = "stage2_training"
    STAGE2_EXTERNAL_IMPORT = "stage2_external_import"   # v0.3: externally published models
    STAGE3_FINETUNE = "stage3_finetune"
    STAGE4_DEPLOYMENT = "stage4_deployment"


STAGE_ORDER: list[str] = [s.value for s in PipelineStage]

# Artifact types whose provenance stops at an outside publisher (trust boundary TB2).
EXTERNAL_TYPES: frozenset[str] = frozenset({ArtifactType.EXTERNAL_BASE_MODEL.value})


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class MerkleInfo(_Strict):
    root: str                       # "sha256:<hex>"
    leaf_count: int
    leaf_unit: str = "csv_line"     # one leaf per line of the file (header included)
    hash: str = "sha256"


class Subject(_Strict):
    uri: str                        # workspace-relative POSIX path
    sha256: str                     # hex digest of the file bytes
    size_bytes: int
    media_type: str
    merkle: MerkleInfo | None = None


class ParentRef(_Strict):
    artifact_id: str
    manifest_digest: str            # "sha256:<hex>" of the parent's canonical payload
    relation: str                   # trained_on | fine_tuned_from | deploys | derived_from


class SemanticCheck(_Strict):
    """Result of a content-level (semantic) check run BEFORE signing.

    These are evidence about the content, not cryptographic guarantees. A ``flag``
    makes verification return WARNING, never FAILED.
    """

    name: str
    status: Literal["pass", "flag", "skip"]
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class SignerInfo(_Strict):
    identity: str                   # e.g. training_pipeline@chainguard.local
    role: str                       # must match the role registered for key_id
    key_id: str                     # "ed25519:<16 hex>"


class ManifestBody(_Strict):
    schema_version: str = SCHEMA_VERSION
    artifact_id: str
    artifact_name: str
    artifact_type: ArtifactType
    version: str
    pipeline_stage: PipelineStage
    subject: Subject
    parents: list[ParentRef] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    semantic_checks: list[SemanticCheck] = Field(default_factory=list)
    created_at: str                 # ISO-8601 UTC, e.g. 2026-10-20T09:14:03Z
    signer: SignerInfo


class SignatureEntry(_Strict):
    key_id: str
    algorithm: str
    sig: str                        # base64


class Envelope(_Strict):
    payload_type: str = PAYLOAD_TYPE
    payload: ManifestBody
    signatures: list[SignatureEntry]
    # Convenience copy for humans and indexes. NEVER trusted: the verifier always
    # recomputes the digest from the payload bytes.
    manifest_digest: str
