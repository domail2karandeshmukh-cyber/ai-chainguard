"""AI-ChainGuard core library.

All security-critical logic (hashing, canonical serialisation, signing, provenance,
verification) lives in this package. The CLI, API, ML pipeline, gateway, attack
scripts and CI are thin consumers of it, so there is exactly one implementation to
test and defend.

Typical use::

    from chainguard.context import ChainGuard
    cg = ChainGuard.open()              # workspace from $CHAINGUARD_HOME or cwd
    cg.trust.init_keys()                # one Ed25519 key pair per role
    res = cg.registry.register("data/train.csv", name="digits-train",
                               artifact_type="dataset", stage="stage1_dataset",
                               role="data_steward")
    report = cg.verifier.verify(res.artifact_id)
    print(report.status)                # VERIFIED / WARNING / FAILED
"""

__version__ = "0.4.0"

import logging as _logging

# Library convention: no output unless the application configures logging.
_logging.getLogger("chainguard").addHandler(_logging.NullHandler())
