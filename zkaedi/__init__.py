"""ZKAEDI: Cryptographic Action Receipts & Tamper-Evident Audit Trails for FastAPI & SQLite."""

from typing import Any

from zkaedi.audited import (
    AuditReceipt,
    AuditRecorder,
    IdempotencyConflict,
    ZkaediMiddleware,
    audited,
    file_checkpoint_sink,
    stdout_checkpoint_sink,
)
from zkaedi.context_bound_epoch_protocol import (
    AuthStatus,
    AuthorizationDatabase,
    AuthorizationRejected,
    CredentialClaims,
    CredentialCodec,
    Ed25519KeyRing,
    IssuanceSnapshot,
    KeyPurpose,
    KeyRecord,
    KeyStatus,
    LinearizableEngine,
    MigrationError,
    __version__,
    advance_epoch,
    canonical_json_object,
    pack_state,
    parse_strict_json,
    unpack_state,
)


def __getattr__(name: str) -> Any:
    if name in ("verify_database", "load_trusted_keys"):
        import zkaedi.verify_cli as _v
        return getattr(_v, name)
    if name == "verify_main":
        import zkaedi.verify_cli as _v
        return _v.main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "audited",
    "ZkaediMiddleware",
    "AuditRecorder",
    "AuditReceipt",
    "file_checkpoint_sink",
    "stdout_checkpoint_sink",
    "verify_database",
    "load_trusted_keys",
    "verify_main",
    "AuthStatus",
    "AuthorizationDatabase",
    "AuthorizationRejected",
    "CredentialClaims",
    "CredentialCodec",
    "Ed25519KeyRing",
    "IssuanceSnapshot",
    "KeyPurpose",
    "KeyRecord",
    "KeyStatus",
    "LinearizableEngine",
    "MigrationError",
    "__version__",
    "advance_epoch",
    "canonical_json_object",
    "pack_state",
    "parse_strict_json",
    "unpack_state",
]
