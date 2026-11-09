"""Stage 4: deployment gateway - the last line of defence before production.

Decision logic
--------------
1. Full chain verification (V0-V9, recursive) of the candidate model.
2. FAILED  -> block, log DEPLOYMENT_BLOCKED (critical).
   WARNING -> block unless policy/override allows it; an override is itself logged.
   VERIFIED -> continue.
3. Refuse pickle-based model formats (code execution on load).
4. Read the model bytes ONCE, re-hash them, load the model from those same bytes
   (no time-of-check/time-of-use gap) and run a smoke inference.
5. Compute the release root (Merkle root over the manifest digests of the model and
   all ancestors) and sign a deployment record with the deployment_gateway key.

Run directly:  python -m deployment.gateway --model-id <id> [--allow-warning]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chainguard.context import ChainGuard
from chainguard.events import CRITICAL, INFO, WARNING, EventType, log_event
from chainguard.exceptions import UnverifiedArtifactError
from chainguard.metrics import record, timed
from chainguard.provenance.merkle import release_root
from chainguard.verification.results import Status, VerificationReport
from chainguard.verification.verified_io import open_verified

SAFE_MODEL_MEDIA_TYPES = {"application/safetensors"}
DEPLOYABLE_TYPES = {"finetuned_model", "base_model"}


@dataclass
class GatewayDecision:
    model_id: str
    status: str
    deployed: bool
    reason: str
    report: VerificationReport | None = None
    deployment_record_id: str | None = None
    release_root: str | None = None
    smoke_test: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id, "status": self.status, "deployed": self.deployed,
            "reason": self.reason, "deployment_record_id": self.deployment_record_id,
            "release_root": self.release_root, "smoke_test": self.smoke_test,
            "report": self.report.model_dump(mode="json") if self.report else None,
        }


class DeploymentGateway:
    def __init__(self, cg: ChainGuard):
        self.cg = cg

    def deploy(self, model_id: str, *, environment: str = "staging", allow_warning: bool | None = None,
               test_csv: str | Path | None = None) -> GatewayDecision:
        cg = self.cg
        allow_warning = (not cg.policy.block_on_warning) if allow_warning is None else allow_warning

        # ---- 1-2: verification + TOCTOU-free read ----------------------------------
        # open_verified() verifies the full chain once, then reads the model bytes once
        # and re-checks their hash, so what we load below is exactly what was verified.
        try:
            va = open_verified(cg.verifier, model_id, allow_warning=True, context="gateway")
        except UnverifiedArtifactError as exc:
            report = exc.report
            if report is None:
                raise
            reason = (f"chain verification FAILED ({', '.join(report.failed_checks())})"
                      if report.status == Status.FAILED else str(exc))
            return self._block(model_id, report, reason)
        report = va.report
        name = report.artifact_name or model_id
        if report.status == Status.WARNING and not allow_warning:
            return self._block(model_id, report, "integrity intact but content flagged (WARNING); "
                                                 "blocked by policy")
        if report.status == Status.WARNING:
            log_event(cg.repo, WARNING, EventType.DEPLOYMENT_APPROVED,
                      f"WARNING override used to deploy {name}", artifact_id=model_id)
        if report.artifact_type not in DEPLOYABLE_TYPES:
            return self._block(model_id, report, f"artifact type {report.artifact_type} is not deployable")

        # ---- 3-4: refuse unsafe formats, load from verified bytes, smoke test --------
        if va.body.subject.media_type not in SAFE_MODEL_MEDIA_TYPES:
            return self._block(model_id, report, f"unsafe model format {va.body.subject.media_type} "
                                                 "(pickle can execute code on load)")
        smoke = self._smoke_test(va.data, model_id, test_csv)

        # ---- 5: release root + signed deployment record -----------------------------
        digests = cg.verifier.chain_digests(report)
        root = release_root(digests)
        record_doc = {
            "kind": "chainguard.deployment_record/v1",
            "model_id": model_id,
            "model_name": name,
            "model_manifest_digest": report.manifest_digest,
            "release_root": root,
            "chain": [{"artifact_id": report.artifact_id, "manifest_digest": report.manifest_digest}]
            + [{"artifact_id": a.artifact_id, "name": a.artifact_name, "manifest_digest": a.manifest_digest}
               for a in report.ancestors],
            "environment": environment,
            "verification_status": report.status.value,
            "smoke_test": smoke,
            "decided_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
        path = cg.settings.deployments_dir / f"deploy-{name}-{stamp}.json"
        path.write_text(json.dumps(record_doc, indent=2) + "\n", encoding="utf-8")
        reg = cg.registry.register(
            path, name=f"deployment-{name}", artifact_type="deployment_record", stage="stage4_deployment",
            role="deployment_gateway", parents=[(model_id, "deploys")],
            provenance={"source": "deployment gateway", "builder": "deployment/gateway.py",
                        "release_root": root, "environment": environment},
        )
        log_event(cg.repo, INFO, EventType.DEPLOYMENT_APPROVED,
                  f"Deployed {name} to {environment}; release root {root[:23]}...", artifact_id=model_id,
                  details={"deployment_record": reg.artifact_id, "release_root": root})
        return GatewayDecision(model_id=model_id, status=report.status.value, deployed=True,
                               reason="chain verified", report=report, deployment_record_id=reg.artifact_id,
                               release_root=root, smoke_test=smoke)

    def _smoke_test(self, data: bytes, model_id: str, test_csv: str | Path | None) -> dict[str, Any]:
        from ml_pipeline.dataset import read_csv
        from ml_pipeline.evaluate import accuracy, inference_latency_ms
        from ml_pipeline.model import model_from_bytes

        model = model_from_bytes(data)
        csv = Path(test_csv) if test_csv else self.cg.settings.data_dir / "digits_test.csv"
        if not csv.exists():
            return {"ran": False, "reason": "no test set"}
        X, y = read_csv(csv)
        with timed() as t:
            acc = accuracy(model, X, y)
        latency = inference_latency_ms(model, X)
        record(self.cg.repo, "inference", latency, artifact_id=model_id, size_bytes=None, batch=len(X))
        return {"ran": True, "test_accuracy": round(acc, 4), "samples": int(len(X)),
                "batch_latency_ms": round(latency, 3), "eval_ms": round(t.ms, 3)}

    def _block(self, model_id: str, report: VerificationReport, reason: str) -> GatewayDecision:
        log_event(self.cg.repo, CRITICAL, EventType.DEPLOYMENT_BLOCKED,
                  f"Blocked {report.artifact_name or model_id}: {reason}", artifact_id=model_id,
                  details={"status": report.status.value, "failed": report.failed_checks(),
                           "warned": report.warned_checks()})
        return GatewayDecision(model_id=model_id, status=report.status.value, deployed=False,
                               reason=reason, report=report)


def main() -> None:
    ap = argparse.ArgumentParser(description="Stage 4: verify and deploy a model")
    ap.add_argument("--model-id", required=True)
    ap.add_argument("--environment", default="staging")
    ap.add_argument("--allow-warning", action="store_true")
    ap.add_argument("--home", default=None)
    args = ap.parse_args()
    cg = ChainGuard.open(args.home)
    d = DeploymentGateway(cg).deploy(args.model_id, environment=args.environment,
                                     allow_warning=args.allow_warning or None)
    print(json.dumps({k: v for k, v in d.to_dict().items() if k != "report"}, indent=2))
    sys.exit(0 if d.deployed else 1)


if __name__ == "__main__":
    main()
