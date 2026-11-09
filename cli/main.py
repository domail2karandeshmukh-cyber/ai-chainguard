"""AI-ChainGuard command-line interface.

    python -m cli.main keys init                 create/register one key pair per role
    python -m cli.main keys list
    python -m cli.main register FILE --type dataset --stage stage1_dataset --role data_steward
    python -m cli.main verify ARTIFACT_ID [--file CANDIDATE] [--json]
    python -m cli.main list
    python -m cli.main revoke ARTIFACT_ID --reason "..."
    python -m cli.main events
    python -m cli.main mvp-demo                   register -> verify -> tamper -> verify

External models (v0.3, Experiment 7):
    python -m cli.main publisher keygen OUT_DIR                 (publisher side, simulated)
    python -m cli.main publisher sign MODEL --key K --identity ID --name N --out MANIFEST
    python -m cli.main keys trust-publisher PUBKEY_FILE --identity ID
    python -m cli.main import-external MODEL --manifest MANIFEST

Signed trust log and interoperability (v0.4):
    python -m cli.main keys trust-log                           replay and print the signed trust log
    python -m cli.main export ARTIFACT_ID --format intoto|slsa  in-toto Statement in a DSSE envelope

Global option ``--home`` selects the workspace (default $CHAINGUARD_HOME or cwd).
Exit code of ``verify``: 0 VERIFIED, 2 WARNING, 1 FAILED (usable as a CI gate).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer

from chainguard.context import ChainGuard
from chainguard.exceptions import ChainGuardError
from chainguard.verification.results import Status, VerificationReport

app = typer.Typer(help="AI-ChainGuard: AI supply-chain integrity and attestation", no_args_is_help=True)
keys_app = typer.Typer(help="Signing key management", no_args_is_help=True)
app.add_typer(keys_app, name="keys")
publisher_app = typer.Typer(help="SIMULATED outside model publisher (Experiment 7)", no_args_is_help=True)
app.add_typer(publisher_app, name="publisher")

STATE: dict[str, str | None] = {"home": None}
ICON = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "skip"}
EXIT = {Status.VERIFIED: 0, Status.WARNING: 2, Status.FAILED: 1}


@app.callback()
def _global(home: str = typer.Option(None, "--home", help="Workspace root")) -> None:
    STATE["home"] = home


def _cg() -> ChainGuard:
    return ChainGuard.open(STATE["home"])


def print_report(report: VerificationReport) -> None:
    color = {Status.VERIFIED: typer.colors.GREEN, Status.WARNING: typer.colors.YELLOW,
             Status.FAILED: typer.colors.RED}[report.status]
    typer.secho(f"\n  {report.status.value}  {report.artifact_name or report.artifact_id}", fg=color, bold=True)
    typer.echo(f"  id {report.artifact_id}   type {report.artifact_type}   stage {report.pipeline_stage}")
    typer.echo(f"  manifest {report.manifest_digest}\n")
    for c in report.checks:
        typer.echo(f"  [{ICON[c.outcome]:>4}] {c.check_id} {c.name:<38} {c.message}")
    if report.ancestors:
        typer.echo("\n  ancestors:")
        for a in report.ancestors:
            bad = ", ".join(a.failed_checks or a.warned_checks)
            typer.echo(f"    {a.status.value:<8} {a.artifact_type:<16} {a.artifact_name}  {bad}")
    if report.external_artifacts:
        typer.secho(f"\n  EXTERNAL in chain: {', '.join(report.external_artifacts)} - the publisher signature "
                    "proves origin and integrity, not that the model is safe.", fg=typer.colors.CYAN)
    typer.echo(f"\n  verified in {report.duration_ms:.1f} ms\n")


# ---------------------------------------------------------------- keys
@keys_app.command("init")
def keys_init(rotate: bool = typer.Option(False, help="Revoke current keys and create new ones")) -> None:
    """Create (or register) one Ed25519 key pair per role. Private keys go to keys/ (0600)."""
    for k in _cg().trust.init_keys(rotate=rotate):
        typer.echo(f"{k['role']:<20} {k['key_id']}  {k['action']}")


@keys_app.command("list")
def keys_list() -> None:
    for s in _cg().repo.list_signers():
        state = f"REVOKED {s['revoked_at']}" if s["revoked_at"] else "active"
        typer.echo(f"{s['role']:<20} {s['key_id']}  {s['identity']:<40} {state}")


@keys_app.command("trust-log")
def keys_trust_log(as_json: bool = typer.Option(False, "--json")) -> None:
    """Replay the signed, append-only trust log against the pinned root (v0.4)."""
    state = _cg().trust.state()
    if as_json:
        typer.echo(json.dumps({**state.summary(), "entries": state.entries}, indent=2, default=str))
        raise typer.Exit(0 if state.ok else 1)
    if not state.ok:
        typer.secho(f"TRUST LOG INVALID: {state.error}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(1)
    typer.echo(f"root key {state.root_key_id}   head #{state.head_seq} {state.head_hash}   "
               f"replayed in {state.verify_ms:.2f} ms")
    for e in state.entries:
        subj = e["subject"]
        what = subj.get("artifact_id") or f"{subj.get('role', '')} {subj.get('key_id', '')} {subj.get('identity', '')}"
        typer.echo(f"  #{e['seq']:<3} {e['ts'][:19]}  {e['action']:<16} {what.strip()}"
                   + (f"  ({e['reason']})" if e.get("reason") else ""))


@keys_app.command("revoke")
def keys_revoke(key_id: str, reason: str = typer.Option(..., help="Why the key is revoked")) -> None:
    ok = _cg().trust.revoke_key(key_id, reason)
    typer.echo("revoked" if ok else "not found or already revoked")


@keys_app.command("trust-publisher")
def keys_trust_publisher(
    public_key_file: Path = typer.Argument(..., exists=True, dir_okay=False, help="base64 Ed25519 public key"),
    identity: str = typer.Option(..., help="publisher identity, e.g. release-bot@hub.example"),
) -> None:
    """Trust an OUTSIDE model publisher's public key (role model_publisher)."""
    try:
        key_id = _cg().trust.trust_publisher(public_key_file.read_text().strip(), identity)
    except ChainGuardError as exc:
        typer.secho(f"refused: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1) from exc
    typer.echo(f"model_publisher      {key_id}  {identity}  trusted")


# ---------------------------------------------------------------- simulated publisher
@publisher_app.command("keygen")
def publisher_keygen(out_dir: Path = typer.Argument(..., help="where the PUBLISHER keeps its key pair")) -> None:
    """Create a publisher key pair (publisher.pem 0600 + publisher.pub). Not part of our trust store."""
    from chainguard.crypto.keys import compute_key_id, generate_private_key, public_key_b64, save_private_key

    key = generate_private_key()
    save_private_key(key, out_dir / "publisher.pem")
    (out_dir / "publisher.pub").write_text(public_key_b64(key.public_key()) + "\n")
    typer.echo(f"publisher key {compute_key_id(key.public_key())} -> {out_dir}/publisher.pem, publisher.pub")


@publisher_app.command("sign")
def publisher_sign(
    model: Path = typer.Argument(..., exists=True, dir_okay=False),
    key: Path = typer.Option(..., exists=True, dir_okay=False, help="publisher private key (PEM)"),
    identity: str = typer.Option(..., help="publisher identity, e.g. release-bot@hub.example"),
    name: str = typer.Option(None, help="model name (default: file stem)"),
    version: str = typer.Option("1.0.0"),
    out: Path = typer.Option(None, help="manifest path (default: MODEL.manifest.json)"),
) -> None:
    """Publisher side: sign an external model manifest with the publisher's own key."""
    from chainguard.crypto.keys import load_private_key_pem
    from chainguard.external import publish_external_model
    from chainguard.manifest.builder import write_envelope

    env = publish_external_model(model, name=name or model.stem, version=version,
                                 publisher_key=load_private_key_pem(key.read_bytes()), publisher_identity=identity)
    dest = write_envelope(env, out or model.with_name(model.name + ".manifest.json"))
    typer.echo(f"signed {env.payload.artifact_name} as {identity} -> {dest}")


# ---------------------------------------------------------------- artifacts
@app.command("import-external")
def import_external(
    model: Path = typer.Argument(..., exists=True, dir_okay=False),
    manifest: Path = typer.Option(None, help="publisher-signed manifest; omit to see an unsigned model refused"),
) -> None:
    """Import an externally published model, then verify it (Experiment 7)."""
    from chainguard.external import import_external_model

    try:
        res = import_external_model(_cg(), model, manifest, context="cli")
    except ChainGuardError as exc:
        typer.secho(f"\n  REFUSED  {exc}\n", fg=typer.colors.RED, bold=True)
        raise typer.Exit(1) from exc
    print_report(res.report)
    typer.echo(f"  artifact_id {res.artifact_id}  "
               + ("accepted" if res.accepted else "QUARANTINED (cannot be used as a parent or deployed)"))
    raise typer.Exit(EXIT[res.report.status])


@app.command()
def register(
    file: Path = typer.Argument(..., exists=True, dir_okay=False),
    name: str = typer.Option(None, help="Artifact name (default: file stem)"),
    artifact_type: str = typer.Option(..., "--type",
                                      help="dataset | base_model | finetuned_model | deployment_record "
                                           "(external_base_model: use import-external)"),
    stage: str = typer.Option(..., help="stage1_dataset | stage2_training | stage3_finetune | stage4_deployment"),
    role: str = typer.Option(..., help="Signing role, e.g. data_steward"),
    version: str = typer.Option("1.0.0"),
    parent: list[str] = typer.Option([], help="PARENT_ID or PARENT_ID:relation (repeatable)"),
    source: str = typer.Option(None, help="Free-text provenance source"),
    no_checks: bool = typer.Option(False, "--no-checks", help="Skip semantic dataset checks"),
) -> None:
    """Hash, (check), sign and register an artifact."""
    parents = []
    for p in parent:
        pid, _, rel = p.partition(":")
        parents.append((pid, rel or "derived_from"))
    try:
        res = _cg().registry.register(
            file, name=name or file.stem, artifact_type=artifact_type, stage=stage, role=role,
            version=version, parents=parents, provenance={"source": source} if source else None,
            run_semantic_checks=False if no_checks else None)
    except ChainGuardError as exc:
        typer.secho(f"refused: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1) from exc
    typer.echo(f"artifact_id      {res.artifact_id}")
    typer.echo(f"manifest_digest  {res.manifest_digest}")
    typer.echo(f"sha256           {res.sha256}")
    if res.merkle_root:
        typer.echo(f"merkle_root      {res.merkle_root}")
    for c in res.semantic_checks:
        typer.echo(f"check            {c.name}: {c.status} - {c.summary}")
    typer.echo(f"envelope         {res.envelope_path}")


@app.command()
def verify(
    artifact_id: str,
    file: Path = typer.Option(None, help="Verify this candidate file instead of the registered one"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Verify an artifact and its full provenance chain (checks V0-V9)."""
    report = _cg().verifier.verify(artifact_id, file_path=file, context="cli")
    if as_json:
        typer.echo(report.model_dump_json(indent=2))
    else:
        print_report(report)
    raise typer.Exit(EXIT[report.status])


@app.command("list")
def list_artifacts() -> None:
    rows = _cg().repo.list_artifacts()
    for a in rows:
        flag = " REVOKED" if a["revoked"] else ""
        typer.echo(f"{a['artifact_id']}  {a['pipeline_stage']:<18} {a['artifact_type']:<18} "
                   f"{a['artifact_name']:<34} {a['last_status'] or '-':<9}{flag}")
    if not rows:
        typer.echo("no artifacts registered")


@app.command()
def export(
    artifact_id: str,
    fmt: str = typer.Option("intoto", "--format", help="intoto (ChainGuard predicate) | slsa (SLSA Provenance v1)"),
    out: Path = typer.Option(None, help="write the DSSE envelope here (default: print)"),
    unsigned: bool = typer.Option(False, "--unsigned", help="print the bare in-toto Statement"),
) -> None:
    """Export an attestation as an in-toto Statement inside a DSSE envelope (v0.4)."""
    from chainguard.interop import export_attestation, write_attestation

    try:
        if out:
            dest = write_attestation(_cg(), artifact_id, out, fmt)
            typer.echo(f"wrote {dest}")
        else:
            typer.echo(json.dumps(export_attestation(_cg(), artifact_id, fmt, sign=not unsigned), indent=2))
    except ChainGuardError as exc:
        typer.secho(f"refused: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1) from exc


@app.command()
def revoke(artifact_id: str, reason: str = typer.Option(...)) -> None:
    ok = _cg().registry.revoke(artifact_id, reason)
    typer.echo("revoked" if ok else "already revoked")


@app.command()
def events(limit: int = 30) -> None:
    for e in reversed(_cg().repo.list_events(limit=limit)):
        typer.echo(f"{e['ts'][:19]}  {e['severity']:<8} {e['event_type']:<22} {e['message']}")


@app.command("mvp-demo")
def mvp_demo() -> None:
    """The MVP in one command: register -> verify (VERIFIED) -> tamper -> verify (FAILED)."""
    cg = _cg()
    cg.trust.init_keys()
    src = cg.settings.data_dir / "mvp_sample.csv"
    sample = Path(__file__).resolve().parents[1] / "data" / "samples" / "mvp_sample.csv"
    shutil.copyfile(sample, src)
    res = cg.registry.register(src, name="mvp-sample", artifact_type="dataset", stage="stage1_dataset",
                               role="data_steward")
    typer.echo(f"1. registered {res.artifact_id} (sha256 {res.sha256[:16]}...)")
    first = cg.verifier.verify(res.artifact_id, context="mvp")
    print_report(first)
    lines = src.read_text().splitlines()
    lines[1] = lines[1].rsplit(",", 1)[0] + ",9"   # flip one label
    src.write_text("\n".join(lines) + "\n")
    typer.echo("2. tampered: changed the label of the first data row")
    second = cg.verifier.verify(res.artifact_id, context="mvp")
    print_report(second)
    ok = first.status != Status.FAILED and second.status == Status.FAILED
    typer.secho("MVP demo OK: tampering detected" if ok else "MVP demo FAILED",
                fg=typer.colors.GREEN if ok else typer.colors.RED)
    report_json = cg.settings.results_dir / "mvp_demo.json"
    report_json.write_text(json.dumps({"before": first.model_dump(mode="json"),
                                       "after": second.model_dump(mode="json")}, indent=2))
    raise typer.Exit(0 if ok else 1)


if __name__ == "__main__":
    app()
