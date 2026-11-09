"""Provenance graph helpers.

The authoritative graph is the set of signed envelopes: each payload embeds its
parents' manifest digests, which makes the graph *hash-linked* (changing any
ancestor changes every descendant's expected digest). The SQLite ``artifact_parents``
table is a copy used for fast queries and the dashboard; the verifier never trusts it.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from functools import lru_cache
from typing import Any

from chainguard import __version__
from chainguard.config import REPO_ROOT
from chainguard.storage.repository import Repository


def build_environment(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Describe the environment that produced an artifact (recorded in provenance).

    This is a *claim* by the builder, signed by its key. Without hardware attestation
    (TEE) it cannot prove the code actually ran in this environment: a compromised
    builder can lie. That residual risk is documented in the threat model.
    """
    env: dict[str, Any] = {
        "python": platform.python_version(),
        "platform": f"{sys.platform}-{platform.machine()}",
        "chainguard": __version__,
        "builder_commit": git_commit(),
        "ci_run_id": os.environ.get("GITHUB_RUN_ID"),
    }
    try:
        import torch  # optional: only present in the ML pipeline

        env["torch"] = torch.__version__
    except ImportError:
        pass
    if extra:
        env.update(extra)
    return env


@lru_cache(maxsize=1)
def git_commit() -> str:
    """Commit of the code base that produced the artifact (cached: one git call per process)."""
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                             text=True, timeout=5, check=False)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def lineage(repo: Repository, artifact_id: str) -> dict[str, list[str]]:
    """Ancestors and descendants of an artifact according to the index."""
    def walk(start: str, step) -> list[str]:
        seen: list[str] = []
        frontier = [start]
        while frontier:
            current = frontier.pop()
            for nxt in step(current):
                if nxt not in seen and nxt != start:
                    seen.append(nxt)
                    frontier.append(nxt)
        return seen

    return {
        "ancestors": walk(artifact_id, lambda a: [lk["parent_id"] for lk in repo.get_parent_links(a)]),
        "descendants": walk(artifact_id, lambda a: [lk["child_id"] for lk in repo.get_child_links(a)]),
    }


def graph(repo: Repository) -> dict[str, list[dict[str, Any]]]:
    """Nodes and edges of the whole provenance graph (for the dashboard)."""
    nodes = [{
        "artifact_id": a["artifact_id"], "name": a["artifact_name"], "type": a["artifact_type"],
        "stage": a["pipeline_stage"], "version": a["version"], "status": a["last_status"],
        "revoked": bool(a["revoked"]), "manifest_digest": a["manifest_digest"],
    } for a in repo.list_artifacts()]
    edges = [{"parent": lk["parent_id"], "child": lk["child_id"], "relation": lk["relation"]}
             for lk in repo.all_links()]
    return {"nodes": nodes, "edges": edges}
