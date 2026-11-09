"""Exception hierarchy for AI-ChainGuard.

Verification problems are NOT raised as exceptions: the verifier always returns a
full report so that every failed check is visible. Exceptions are used for
operations that must stop (bad input, missing key, policy violation at registration).
"""


class ChainGuardError(Exception):
    """Base class for all AI-ChainGuard errors."""


class ConfigError(ChainGuardError):
    """Invalid configuration or path outside the workspace."""


class ArtifactNotFoundError(ChainGuardError):
    """An artifact id is unknown to the registry index or its envelope is missing."""


class KeyNotFoundError(ChainGuardError):
    """No usable private key exists for a signing role."""


class KeyMismatchError(ChainGuardError):
    """A private key does not match the public key registered in the trust store."""


class PolicyViolationError(ChainGuardError):
    """A registration would break the supply-chain policy (stage, role, parents)."""


class RegistrationError(ChainGuardError):
    """Registration refused, e.g. because a parent artifact failed verification."""


class ExternalImportError(RegistrationError):
    """An external (third-party) model was refused at import, e.g. unsigned (v0.3)."""


class ManifestError(ChainGuardError):
    """A manifest or envelope is malformed."""


class TrustLogError(ChainGuardError):
    """The signed trust log cannot be written or is not initialised (v0.4)."""


class UnverifiedArtifactError(ChainGuardError):
    """An artifact was about to be consumed but did not pass verification."""

    def __init__(self, message: str, report=None):  # report: VerificationReport
        super().__init__(message)
        self.report = report
