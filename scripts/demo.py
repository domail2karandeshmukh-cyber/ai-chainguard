"""The 10-minute professor demo, in one command.

    python -m scripts.demo            # pauses after each step: press Enter to continue
    python -m scripts.demo --auto     # runs straight through (rehearsal, Docker, CI)
    make demo                         # same as the first line

Everything happens in a throw-away workspace (default: ./demo-ws, recreated each run),
so the demo never touches your real keys or artifacts. Every number printed is
measured live during the run - nothing is pre-written.

Steps (13): clean chain -> verify -> VERIFIED -> provenance -> tamper -> verify again
-> FAILED -> gateway BLOCKED -> invalid signature -> revocation -> poisoned before
signing (the limitation) -> trusted vs untrusted external model -> metrics.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import statistics
import time
from pathlib import Path
from typing import Any

import typer

from chainguard.config import REPO_ROOT
from chainguard.context import ChainGuard
from chainguard.verification.results import VerificationReport

MARKER = ".chainguard-demo-workspace"
COLOR = {"VERIFIED": typer.colors.GREEN, "WARNING": typer.colors.YELLOW, "FAILED": typer.colors.RED,
         "REFUSED": typer.colors.MAGENTA, "BLOCKED": typer.colors.RED, "DEPLOYED": typer.colors.GREEN}
STATE: dict[str, Any] = {"auto": False, "step": 0, "shown": []}
TOTAL = 13


# ---------------------------------------------------------------- presentation helpers
def step(title: str, say: str) -> None:
    STATE["step"] += 1
    typer.echo("")
    typer.secho("=" * 78, fg=typer.colors.BLUE)
    typer.secho(f" STEP {STATE['step']}/{TOTAL}  {title}", fg=typer.colors.BLUE, bold=True)
    typer.secho("=" * 78, fg=typer.colors.BLUE)
    typer.secho(f" SAY: {say}", fg=typer.colors.CYAN)
    typer.echo("")


def pause() -> None:
    if not STATE["auto"]:
        input("\n   [Enter] next step ")


def badge(text: str) -> str:
    return typer.style(f" {text} ", fg=typer.colors.WHITE, bg=COLOR.get(text, typer.colors.BLACK), bold=True)


def show(report: VerificationReport, label: str, full: bool = False) -> None:
    bad = report.failed_checks() or report.warned_checks()
    typer.echo(f"   {badge(report.status.value)}  {label}   "
               + (f"failed/warned checks: {', '.join(bad)}" if bad else "all checks passed")
               + f"   ({report.duration_ms:.1f} ms, whole chain)")
    if full:
        for c in report.checks:
            mark = {"pass": "ok  ", "fail": "FAIL", "warn": "WARN", "skip": "skip"}[c.outcome]
            typer.echo(f"      [{mark}] {c.check_id} {c.name:<36} {c.message[:90]}")
    elif bad:
        for c in report.checks:
            if c.outcome in ("fail", "warn"):
                typer.echo(f"      {c.check_id}: {c.message[:110]}")
    STATE["shown"].append((STATE["step"], label, report.status.value))


def gateway(cg: ChainGuard, model_id: str, label: str) -> bool:
    from deployment.gateway import DeploymentGateway

    d = DeploymentGateway(cg).deploy(model_id)
    verdict = "DEPLOYED" if d.deployed else "BLOCKED"
    typer.echo(f"   gateway decision for {label}: {badge(verdict)}  ({d.reason})")
    STATE["shown"].append((STATE["step"], f"gateway: {label}", verdict))
    return d.deployed


def subject(cg: ChainGuard, artifact_id: str) -> Path:
    return cg.settings.resolve_uri(cg.repo.get_artifact(artifact_id)["subject_uri"])


def clone(cg: ChainGuard, name: str) -> ChainGuard:
    dst = cg.settings.root / name
    shutil.copytree(cg.settings.root, dst, ignore=shutil.ignore_patterns("_*"))
    return ChainGuard.open(dst)


def quiet(*_: Any) -> None:
    pass


# ---------------------------------------------------------------- the demo
def run(home: Path, auto: bool) -> int:
    from chainguard.crypto.keys import generate_private_key, public_key_b64
    from chainguard.exceptions import ExternalImportError
    from chainguard.external import import_external_model, publish_external_model
    from chainguard.manifest.builder import write_envelope
    from ml_pipeline.dataset import read_csv
    from ml_pipeline.model import load_model
    from ml_pipeline.run_pipeline import run_full_pipeline

    STATE.update(auto=auto, step=0, shown=[])
    if home.exists():
        if not (home / MARKER).exists():
            raise SystemExit(f"{home} exists and is not a demo workspace; refusing to delete it")
        shutil.rmtree(home)
    home.mkdir(parents=True)
    (home / MARKER).write_text("throw-away workspace created by scripts/demo.py\n")
    started = time.perf_counter()

    typer.secho("\nAI-ChainGuard - 10-minute demo. Building a clean, attested 4-stage chain (~10 s) ...",
                bold=True)
    cg = ChainGuard.open(home)
    pipe = run_full_pipeline(cg, log=quiet)
    ids = pipe["artifacts"]
    final, base, train = ids["final_model"], ids["base_model"], ids["train_dataset"]

    # 1 ---------------------------------------------------------------------------------
    step("Clean supply chain",
         "Four AI artifacts, each hashed (SHA-256) and signed (Ed25519) by the role allowed to sign it.")
    signer_role = {s["key_id"]: s["role"] for s in cg.repo.list_signers()}
    for a in cg.repo.list_artifacts():
        typer.echo(f"   {a['pipeline_stage']:<18} {a['artifact_type']:<18} {a['artifact_name']:<32} "
                   f"signed by {signer_role.get(a['signer_key_id'], '?')}")
    typer.echo(f"\n   clean test accuracy of the final model: {pipe['evaluation']['final']['clean_accuracy']:.3f}")
    pause()

    # 2-3 -------------------------------------------------------------------------------
    step("Verify the final model",
         "Verification recomputes every hash and signature of the model AND all its ancestors (V0-V9).")
    show(cg.verifier.verify(final, context="demo"), "fine-tuned model", full=True)
    pause()
    step("Result: VERIFIED",
         "VERIFIED means: exactly what trusted signers attested, through an intact chain. Not 'safe'.")
    typer.echo(f"   {badge('VERIFIED')}  and the gateway already deployed it during the pipeline run:")
    dep = pipe["deployment"]
    typer.echo(f"   deployment record {dep['deployment_record_id']}   release root {dep['release_root'][:30]}...")
    pause()

    # 4 ---------------------------------------------------------------------------------
    step("Provenance",
         "Each child embeds its parents' manifest digests inside its SIGNED payload: a hash-linked chain.")

    def tree(aid: str, depth: int = 0) -> None:
        row = cg.repo.get_artifact(aid)
        typer.echo(f"   {'    ' * depth}{'└── ' if depth else ''}{row['artifact_name']}  ({row['artifact_type']})"
                   f"  manifest {row['manifest_digest'][:23]}...")
        for link in cg.repo.get_parent_links(aid):
            typer.echo(f"   {'    ' * (depth + 1)}   [{link['relation']}] parent digest "
                       f"{link['parent_manifest_digest'][:23]}...")
            tree(link["parent_id"], depth + 1)

    tree(final)
    pause()

    # 5-8 -------------------------------------------------------------------------------
    step("Tamper with the training dataset",
         "An attacker with storage access changes ONE label in the signed training data.")
    ds_path = subject(cg, train)
    original = ds_path.read_bytes()
    lines = original.decode().splitlines()
    head, _, label = lines[5].rpartition(",")
    lines[5] = f"{head},{(int(label) + 1) % 10}"
    ds_path.write_text("\n".join(lines) + "\n")
    typer.echo(f"   changed line 5 of {ds_path.name}: label {label} -> {(int(label) + 1) % 10}")
    pause()
    step("Verify again", "Same command as before.")
    show(cg.verifier.verify(train, context="demo"), "training dataset")
    show(cg.verifier.verify(final, context="demo"), "fine-tuned model")
    pause()
    step("Result: FAILED",
         "The dataset fails V1 (file hash) and V2 (Merkle root names the changed line); the model fails "
         "through V6 because its ancestor failed.")
    typer.echo("   Tampering upstream invalidates everything downstream.")
    pause()
    step("Deployment BLOCKED", "The deployment gateway verifies the chain before loading the model.")
    gateway(cg, final, "fine-tuned model (tampered ancestor)")
    ds_path.write_bytes(original)
    typer.echo("\n   restoring the original dataset bytes ...")
    show(cg.verifier.verify(final, context="demo"), "fine-tuned model after restore")
    pause()

    # 9 ---------------------------------------------------------------------------------
    step("Invalid signature",
         "Now the bytes are intact but the signature is not: one bit of the model's signature flipped.")
    env_path = cg.settings.envelope_path(final)
    env_text = env_path.read_text()
    raw = json.loads(env_text)
    sig = bytearray(base64.b64decode(raw["signatures"][0]["sig"]))
    sig[7] ^= 0x01
    raw["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
    env_path.write_text(json.dumps(raw, indent=2))
    show(cg.verifier.verify(final, context="demo"), "fine-tuned model, corrupted signature")
    env_path.write_text(env_text)
    typer.echo("   (signature restored)")
    pause()

    # 10 --------------------------------------------------------------------------------
    step("Revocation",
         "The base model is withdrawn (e.g. licence or incident). Revocation propagates to descendants.")
    rev = clone(cg, "_revocation")
    rev.registry.revoke(base, "base model withdrawn (demo)")
    show(rev.verifier.verify(final, context="demo"), "fine-tuned model, base model revoked")
    gateway(rev, final, "fine-tuned model (revoked ancestor)")
    typer.echo("   (done in a copy of the workspace so the next steps start clean)")
    pause()

    # 11 --------------------------------------------------------------------------------
    step("The limitation: poisoned BEFORE signing",
         "If the data is poisoned before the data steward signs it, every signature is valid. "
         "Crypto proves integrity, not safety.")
    X, y = read_csv(cg.settings.data_dir / "digits_test.csv")
    rows = []
    for name, checks in (("_poison_no_checks", False), ("_poison_checks", True)):
        pcg = ChainGuard.open(home / name)
        out = run_full_pipeline(pcg, poison_rate=0.08, semantic_checks=checks, log=quiet)
        rep = pcg.verifier.verify(out["artifacts"]["final_model"], context="demo")
        rows.append((checks, rep.status.value, out["deployment"]["deployed"], out["evaluation"]["final"]))
    clean_asr = pipe["evaluation"]["final"]["attack_success_rate"]
    typer.echo(f"   clean model:                 attack success rate {clean_asr:.0%}")
    for checks, status, deployed, ev in rows:
        typer.echo(f"   8% poison, content checks {'ON ' if checks else 'OFF'}: {badge(status)} "
                   f"{badge('DEPLOYED' if deployed else 'BLOCKED')}  clean acc {ev['clean_accuracy']:.0%}, "
                   f"backdoor success {ev['attack_success_rate']:.0%}")
        STATE["shown"].append((STATE["step"], f"poison before signing, checks {'on' if checks else 'off'}",
                               status))
    typer.echo("   Content checks are heuristic evidence (WARNING only); an adaptive trigger evades them "
               "(scenario E4).")
    pause()

    # 12 --------------------------------------------------------------------------------
    step("External models: trusted vs untrusted publisher",
         "A pretrained model from outside has no dataset lineage; we accept it only with a valid "
         "signature from a publisher key we registered.")
    pub_dir = home / "_publisher"
    pub_dir.mkdir()
    trusted = generate_private_key()
    cg.trust.trust_publisher(public_key_b64(trusted.public_key()), "release-bot@trusted-hub.example")
    rogue = generate_private_key()
    weights = subject(cg, base)
    for fname, key, ident in (("hub-cnn.safetensors", trusted, "release-bot@trusted-hub.example"),
                              ("mirror-cnn.safetensors", rogue, "uploader@unknown-mirror.example")):
        model = pub_dir / fname
        shutil.copyfile(weights, model)
        env = publish_external_model(model, name=model.stem, publisher_key=key, publisher_identity=ident)
        res = import_external_model(cg, model, write_envelope(env, pub_dir / f"{fname}.manifest.json"),
                                    context="demo")
        show(res.report, f"external model signed by {ident}")
    unsigned = pub_dir / "unsigned-cnn.safetensors"
    shutil.copyfile(weights, unsigned)
    try:
        import_external_model(cg, unsigned, None, context="demo")
    except ExternalImportError as exc:
        typer.echo(f"   {badge('REFUSED')}  unsigned external model   ({exc})")
        STATE["shown"].append((STATE["step"], "unsigned external model", "REFUSED"))
    typer.echo("   Limitation: a TRUSTED publisher can still ship a backdoored model (scenario G, E7-F).")
    pause()

    # 13 --------------------------------------------------------------------------------
    step("Metrics (measured now, on this machine)",
         "Verification happens once, at deployment - not before every prediction.")
    import numpy as np
    import torch

    o = pipe["overhead"]
    typer.echo(f"   attestation of 4 artifacts: {o['attestation_ms']:.1f} ms vs training {o['training_ms']:.0f} ms "
               f"({o['attestation_vs_training_pct']:.2f}% - small CPU model, workload-dependent)")
    ver = [cg.verifier.verify(final, record_run=False).duration_ms for _ in range(30)]
    model = load_model(subject(cg, final))
    x1 = torch.from_numpy(X[:1].astype(np.float32))
    with torch.no_grad():
        for _ in range(20):
            model(x1)
        inf = []
        for _ in range(300):
            t0 = time.perf_counter()
            model(x1)
            inf.append((time.perf_counter() - t0) * 1000)
    typer.echo(f"   full chain verification: median {statistics.median(ver):.2f} ms (n=30)")
    typer.echo(f"   one prediction:          median {statistics.median(inf):.3f} ms (n=300), "
               "no verification on this path")
    typer.echo(f"   signed manifest of the final model: {cg.settings.envelope_path(final).stat().st_size:,} bytes "
               f"for a {subject(cg, final).stat().st_size:,}-byte model")
    bench = REPO_ROOT / "results" / "metrics" / "inference_benchmark.json"
    if bench.exists():
        b = json.loads(bench.read_text())
        typer.echo(f"   full benchmark on file: results/metrics/inference_benchmark.json "
                   f"({b['machine']['machine_label']}; figure results/figures/fig_inference_overhead.png)")

    # summary ---------------------------------------------------------------------------
    typer.echo("")
    typer.secho("=" * 78, fg=typer.colors.BLUE)
    typer.secho(" SUMMARY", fg=typer.colors.BLUE, bold=True)
    for n, label, status in STATE["shown"]:
        typer.echo(f"   step {n:>2}  {badge(status):<24} {label}")
    if auto:
        typer.echo(f"\n   demo ran in {time.perf_counter() - started:.0f} s of computation")
    typer.secho(" Integrity and provenance: proven. Semantic safety: not proven by signatures.", bold=True)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="AI-ChainGuard 10-minute demo")
    ap.add_argument("--auto", action="store_true", help="no pauses")
    ap.add_argument("--home", default=None, help="demo workspace (default ./demo-ws, recreated each run)")
    args = ap.parse_args()
    default = Path(os.environ.get("CHAINGUARD_HOME") or REPO_ROOT) / "demo-ws"
    raise SystemExit(run(Path(args.home) if args.home else default, args.auto))


if __name__ == "__main__":
    main()
