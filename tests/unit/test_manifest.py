import pytest
from pydantic import ValidationError

from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.keys import compute_key_id, generate_private_key, public_key_b64
from chainguard.crypto.signing import verify_bytes
from chainguard.manifest.builder import build_body, compute_manifest_digest, payload_dict, sign_body
from chainguard.manifest.models import Envelope, ManifestBody


def body(**kw):
    k = kw.pop("key", None) or generate_private_key()
    args = dict(artifact_name="x", artifact_type="dataset", version="1.0.0", pipeline_stage="stage1_dataset",
                subject_uri="data/x.csv", sha256="00" * 32, size_bytes=1, media_type="text/csv",
                signer_identity="data_steward@test", signer_role="data_steward",
                key_id=compute_key_id(k.public_key()))
    args.update(kw)
    return build_body(**args), k


def test_digest_is_deterministic_and_content_sensitive():
    b, k = body(artifact_id="fixed", created_at="2026-01-01T00:00:00Z")
    b2, _ = body(artifact_id="fixed", created_at="2026-01-01T00:00:00Z", key=k)
    assert compute_manifest_digest(b) == compute_manifest_digest(b2)
    b3, _ = body(artifact_id="fixed", created_at="2026-01-01T00:00:00Z", version="1.0.1", key=k)
    assert compute_manifest_digest(b) != compute_manifest_digest(b3)


def test_signature_covers_whole_payload():
    b, k = body()
    env = sign_body(b, k)
    data = canonical_json(payload_dict(b))
    assert verify_bytes(public_key_b64(k.public_key()), data, env.signatures[0].sig)
    tampered = payload_dict(b)
    tampered["pipeline_stage"] = "stage4_deployment"   # change metadata, keep the hash
    assert not verify_bytes(public_key_b64(k.public_key()), canonical_json(tampered), env.signatures[0].sig)


def test_envelope_roundtrip_preserves_digest():
    b, k = body()
    env = sign_body(b, k)
    again = Envelope.model_validate(env.model_dump(mode="json"))
    assert compute_manifest_digest(again.payload) == env.manifest_digest


def test_unknown_fields_rejected():
    b, _ = body()
    raw = payload_dict(b)
    raw["is_safe"] = True
    with pytest.raises(ValidationError):
        ManifestBody.model_validate(raw)


def test_invalid_enum_rejected():
    with pytest.raises(ValidationError):
        body(artifact_type="malware")
