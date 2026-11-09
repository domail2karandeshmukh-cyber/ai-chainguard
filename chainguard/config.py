"""Workspace settings.

A *workspace* is one directory holding everything a ChainGuard instance needs::

    <root>/
      data/                    raw and exported datasets
      artifacts/models/        model weights (.safetensors)
      artifacts/deployments/   signed deployment records
      artifacts/manifests/     signed envelopes (<artifact_id>.json) = source of truth
      artifacts/chainguard.db  SQLite index (mutable state: status, revocation, events)
      keys/                    private signing keys (git-ignored, mode 0600)
      results/                 metrics, attack results, figures

Settings are passed explicitly (dependency injection) instead of being global, so
tests and attack simulations can run in isolated temporary workspaces.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from chainguard.exceptions import ConfigError

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = REPO_ROOT / "config" / "policy.yaml"


@dataclass(frozen=True)
class Settings:
    root: Path
    policy_path: Path = field(default=DEFAULT_POLICY_PATH)
    identity_domain: str = "chainguard.local"

    # ---- standard locations -------------------------------------------------
    @property
    def data_dir(self) -> Path:
        return self.root / "data"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def models_dir(self) -> Path:
        return self.artifacts_dir / "models"

    @property
    def deployments_dir(self) -> Path:
        return self.artifacts_dir / "deployments"

    @property
    def manifests_dir(self) -> Path:
        return self.artifacts_dir / "manifests"

    @property
    def db_path(self) -> Path:
        return self.artifacts_dir / "chainguard.db"

    @property
    def keys_dir(self) -> Path:
        return self.root / "keys"

    @property
    def results_dir(self) -> Path:
        return self.root / "results"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.models_dir, self.deployments_dir, self.manifests_dir,
                  self.results_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        # Private keys directory readable by the owner only (no effect on Windows).
        try:
            os.chmod(self.keys_dir, 0o700)
        except OSError:
            pass

    # ---- path <-> URI ------------------------------------------------------
    def to_uri(self, path: str | Path) -> str:
        """Convert a file path to a workspace-relative POSIX URI stored in manifests.

        Relative URIs keep manifests portable (laptop, Docker volume, CI runner).
        Files outside the workspace are refused: the platform only attests what it
        controls.
        """
        p = Path(path)
        if not p.is_absolute():
            p = (Path.cwd() / p)
        p = p.resolve()
        try:
            rel = p.relative_to(self.root.resolve())
        except ValueError as exc:
            raise ConfigError(f"{p} is outside the workspace {self.root}") from exc
        return PurePosixPath(*rel.parts).as_posix()

    def resolve_uri(self, uri: str) -> Path:
        """Convert a manifest URI back to a path, refusing path traversal."""
        pure = PurePosixPath(uri)
        if pure.is_absolute() or ".." in pure.parts:
            raise ConfigError(f"Refusing unsafe artifact URI: {uri!r}")
        return self.root.joinpath(*pure.parts)

    def envelope_path(self, artifact_id: str) -> Path:
        return self.manifests_dir / f"{artifact_id}.json"

    def leaves_path(self, artifact_id: str) -> Path:
        """Sidecar file with a dataset's Merkle leaf hashes (authenticated by the signed root)."""
        return self.manifests_dir / f"{artifact_id}.leaves.json"


def load_settings(root: str | Path | None = None, policy_path: str | Path | None = None) -> Settings:
    """Build settings from arguments, then environment variables, then defaults."""
    root_path = Path(root or os.environ.get("CHAINGUARD_HOME") or Path.cwd()).resolve()
    policy = Path(policy_path or os.environ.get("CHAINGUARD_POLICY") or DEFAULT_POLICY_PATH)
    if not policy.is_absolute():
        policy = (REPO_ROOT / policy) if (REPO_ROOT / policy).exists() else policy.resolve()
    domain = os.environ.get("CHAINGUARD_IDENTITY_DOMAIN", "chainguard.local")
    return Settings(root=root_path, policy_path=policy, identity_domain=domain)
