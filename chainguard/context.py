"""One object that wires the core components together for a workspace."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from chainguard.config import Settings, load_settings
from chainguard.provenance.policy import Policy
from chainguard.registry import Registry
from chainguard.storage.repository import Repository
from chainguard.trust import TrustStore
from chainguard.trustlog import TrustLog
from chainguard.verification.verifier import Verifier


@dataclass
class ChainGuard:
    settings: Settings
    repo: Repository
    policy: Policy
    trust: TrustStore
    verifier: Verifier
    registry: Registry

    @classmethod
    def open(cls, root: str | Path | None = None, policy_path: str | Path | None = None) -> ChainGuard:
        settings = load_settings(root, policy_path)
        return cls.from_settings(settings)

    @classmethod
    def from_settings(cls, settings: Settings) -> ChainGuard:
        settings.ensure_dirs()
        repo = Repository(settings.db_path)
        policy = Policy.load(settings.policy_path)
        log = TrustLog(settings)                      # v0.4: one signed trust log per workspace
        trust = TrustStore(settings, repo, log)
        verifier = Verifier(settings, repo, policy, log)
        registry = Registry(settings, repo, policy, trust, verifier)
        return cls(settings, repo, policy, trust, verifier, registry)
