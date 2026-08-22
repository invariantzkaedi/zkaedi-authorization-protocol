from __future__ import annotations

import argparse
import cmath
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import unicodedata
import unittest
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


if sys.version_info < (3, 11):  # pragma: no cover
    raise RuntimeError("zkaedi_authorization_v26 requires CPython 3.11+")

if sqlite3.sqlite_version_info < (3, 37, 0):  # pragma: no cover
    raise RuntimeError(f"SQLite 3.37.0+ required for STRICT table security; found {sqlite3.sqlite_version}")

__version__ = "26.0.0"
PROTOCOL_VERSION = 0x40
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
MAX_TIMESTAMP = 0x7FFFFFFFFFFFFFFF
MAX_CREDENTIAL_LIFETIME_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 30
MAX_CONTEXT_BYTES = 1024
MAX_REQUEST_BYTES = 1_048_576
MAX_AUDIT_PAYLOAD_BYTES = 16_384

GEN_SHIFT, GEN_WIDTH = 48, 16
ID_SHIFT, ID_WIDTH = 36, 12
ROLE_SHIFT, ROLE_WIDTH = 24, 12
DEV_SHIFT, DEV_WIDTH = 12, 12
SESS_SHIFT, SESS_WIDTH = 0, 12
GEN_MASK = 0xFFFF
EPOCH_MASK = 0xFFF
KEY_ID_SIZE = 16
CREDENTIAL_ID_SIZE = 16
SHA256_SIZE = 32
ED25519_SIGNATURE_SIZE = 64

VALID_EPOCH_FIELDS: Mapping[str, tuple[int, int]] = {
    "identity": (ID_SHIFT, ID_WIDTH),
    "role": (ROLE_SHIFT, ROLE_WIDTH),
    "device": (DEV_SHIFT, DEV_WIDTH),
    "session": (SESS_SHIFT, SESS_WIDTH),
}

CREDENTIAL_PAYLOAD = struct.Struct(
    ">B16sQQQQQ16s32s32s32s32s32s32s"
)
EXPECTED_PAYLOAD_SIZE = CREDENTIAL_PAYLOAD.size
EXPECTED_TOKEN_SIZE = EXPECTED_PAYLOAD_SIZE + ED25519_SIGNATURE_SIZE


class AuthStatus(str, Enum):
    COMMIT_SUCCESS = "COMMIT_SUCCESS"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    REJECT_MALFORMED_PAYLOAD = "REJECT_MALFORMED_PAYLOAD"
    REJECT_UNKNOWN_KEY = "REJECT_UNKNOWN_KEY"
    REJECT_INVALID_SIGNATURE = "REJECT_INVALID_SIGNATURE"
    REJECT_VERSION_MISMATCH = "REJECT_VERSION_MISMATCH"
    REJECT_INVALID_CURRENT_TIME = "REJECT_INVALID_CURRENT_TIME"
    REJECT_INVALID_TIME_WINDOW = "REJECT_INVALID_TIME_WINDOW"
    REJECT_LIFETIME_EXCEEDED = "REJECT_LIFETIME_EXCEEDED"
    REJECT_ISSUED_IN_FUTURE = "REJECT_ISSUED_IN_FUTURE"
    REJECT_NOT_YET_VALID = "REJECT_NOT_YET_VALID"
    REJECT_EXPIRED = "REJECT_EXPIRED"
    REJECT_ISSUER_MISMATCH = "REJECT_ISSUER_MISMATCH"
    REJECT_PRINCIPAL_MISMATCH = "REJECT_PRINCIPAL_MISMATCH"
    REJECT_AUDIENCE_MISMATCH = "REJECT_AUDIENCE_MISMATCH"
    REJECT_SCOPE_MISMATCH = "REJECT_SCOPE_MISMATCH"
    REJECT_REQUEST_DIGEST_MISMATCH = "REJECT_REQUEST_DIGEST_MISMATCH"
    REJECT_UNKNOWN_PRINCIPAL = "REJECT_UNKNOWN_PRINCIPAL"
    REJECT_UNKNOWN_ISSUER = "REJECT_UNKNOWN_ISSUER"
    REJECT_UNKNOWN_POLICY = "REJECT_UNKNOWN_POLICY"
    REJECT_STATE_MISMATCH = "REJECT_STATE_MISMATCH"
    REJECT_ISSUER_EPOCH_MISMATCH = "REJECT_ISSUER_EPOCH_MISMATCH"
    REJECT_POLICY_MISMATCH = "REJECT_POLICY_MISMATCH"
    REJECT_CREDENTIAL_CONFLICT = "REJECT_CREDENTIAL_CONFLICT"
    REJECT_INVALID_REQUEST = "REJECT_INVALID_REQUEST"
    REJECT_UNKNOWN_ACCOUNT = "REJECT_UNKNOWN_ACCOUNT"
    REJECT_INSUFFICIENT_FUNDS = "REJECT_INSUFFICIENT_FUNDS"
    REJECT_BALANCE_OVERFLOW = "REJECT_BALANCE_OVERFLOW"
    REJECT_RESULT_TAMPERED = "REJECT_RESULT_TAMPERED"
    REJECT_LEGACY_RESULT_UNVERIFIED = "REJECT_LEGACY_RESULT_UNVERIFIED"
    REJECT_INTERNAL_ERROR = "REJECT_INTERNAL_ERROR"


class AuthorizationRejected(Exception):
    """Internal fail-closed control flow carrying a stable rejection status."""

    def __init__(self, status: AuthStatus, message: str = "") -> None:
        super().__init__(message or status.value)
        self.status = status


class MigrationError(Exception):
    """Raised when database schema migration encounters invalid or unreconciled legacy data."""
    pass


class KeyStatus(str, Enum):
    ACTIVE = "active"
    VERIFY_ONLY = "verify_only"
    RETIRED = "retired"


class KeyPurpose(str, Enum):
    CREDENTIAL_SIGNING = "credential_signing"
    RECEIPT_SIGNING = "receipt_signing"


ALLOWED_KEY_TRANSITIONS: Mapping[KeyStatus, frozenset[KeyStatus]] = {
    KeyStatus.ACTIVE: frozenset({KeyStatus.VERIFY_ONLY}),
    KeyStatus.VERIFY_ONLY: frozenset({KeyStatus.RETIRED}),
    KeyStatus.RETIRED: frozenset(),
}


@dataclass(frozen=True)
class AuthorizationResult:
    timestamp: int
    version: str
    status: AuthStatus
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "version": self.version,
            "status": self.status.value,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True)
class CredentialClaims:
    key_id: bytes
    issuer_epoch: int
    packed_state: int
    issued_at: int
    not_before: int
    expires_at: int
    credential_id: bytes
    issuer_digest: bytes
    principal_digest: bytes
    audience_digest: bytes
    scope_digest: bytes
    request_digest: bytes
    policy_digest: bytes
    token_digest: bytes
    normalized_principal: str


@dataclass(frozen=True)
class IssuanceSnapshot:
    packed_state: int
    issuer_epoch: int
    policy_digest: bytes


@dataclass(frozen=True)
class KeyRecord:
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey | None
    status: KeyStatus
    purpose: KeyPurpose
    issuer_digest: bytes


def validate_timestamp(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer Unix timestamp")
    if not 0 <= value <= MAX_TIMESTAMP:
        raise ValueError(f"{name} must be between 0 and {MAX_TIMESTAMP}")
    return value


def validate_time_window(issued_at: int, not_before: int, expires_at: int) -> None:
    validate_timestamp(issued_at, "issued_at")
    validate_timestamp(not_before, "not_before")
    validate_timestamp(expires_at, "expires_at")
    if not issued_at <= not_before < expires_at:
        raise ValueError("requires issued_at <= not_before < expires_at")
    if expires_at - issued_at > MAX_CREDENTIAL_LIFETIME_SECONDS:
        raise ValueError("credential lifetime exceeds policy")


def normalize_context(text: str, name: str) -> str:
    if not isinstance(text, str):
        raise TypeError(f"{name} must be a string")
    normalized = unicodedata.normalize("NFKC", text)
    if not normalized:
        raise ValueError(f"{name} cannot be empty")
    if len(normalized.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ValueError(f"{name} exceeds {MAX_CONTEXT_BYTES} UTF-8 bytes")
    if any(unicodedata.category(char).startswith("C") for char in normalized):
        raise ValueError(f"{name} contains a forbidden control character")
    return normalized


def pack_state(
    generation: int,
    identity: int,
    role: int,
    device: int,
    session: int,
) -> int:
    values = {
        "generation": (generation, GEN_MASK),
        "identity": (identity, EPOCH_MASK),
        "role": (role, EPOCH_MASK),
        "device": (device, EPOCH_MASK),
        "session": (session, EPOCH_MASK),
    }
    for name, (value, maximum) in values.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
        if not 0 <= value <= maximum:
            raise ValueError(f"{name} must be between 0 and {maximum}")
    return (
        (generation << GEN_SHIFT)
        | (identity << ID_SHIFT)
        | (role << ROLE_SHIFT)
        | (device << DEV_SHIFT)
        | (session << SESS_SHIFT)
    )


def unpack_state(packed_word: int) -> tuple[int, int, int, int, int]:
    if not isinstance(packed_word, int) or isinstance(packed_word, bool):
        raise TypeError("packed_word must be an integer")
    if not 0 <= packed_word <= UINT64_MAX:
        raise ValueError("packed_word must be an unsigned 64-bit integer")
    return (
        (packed_word >> GEN_SHIFT) & GEN_MASK,
        (packed_word >> ID_SHIFT) & EPOCH_MASK,
        (packed_word >> ROLE_SHIFT) & EPOCH_MASK,
        (packed_word >> DEV_SHIFT) & EPOCH_MASK,
        (packed_word >> SESS_SHIFT) & EPOCH_MASK,
    )


def advance_epoch(packed_word: int, field: str) -> int:
    unpacked = unpack_state(packed_word)
    if field not in VALID_EPOCH_FIELDS:
        raise ValueError(f"unknown epoch field: {field}")
    generation, identity, role, device, session = unpacked
    shift, width = VALID_EPOCH_FIELDS[field]
    mask = (1 << width) - 1
    current = (packed_word >> shift) & mask
    if current < mask:
        return (packed_word & ~(mask << shift)) | ((current + 1) << shift)
    if generation >= GEN_MASK:
        raise OverflowError("generation exhausted; principal rekey required")
    epochs = {
        "identity": identity,
        "role": role,
        "device": device,
        "session": session,
    }
    epochs[field] = 1
    return pack_state(
        generation + 1,
        epochs["identity"],
        epochs["role"],
        epochs["device"],
        epochs["session"],
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_integer(text: str) -> int:
    value = int(text)
    if not -(1 << 63) <= value <= (1 << 63) - 1:
        raise ValueError("JSON integer exceeds signed 64-bit range")
    return value


def _reject_non_integer_number(text: str) -> None:
    raise ValueError(f"non-integer JSON number rejected: {text}")


def parse_strict_json(request_bytes: bytes) -> Any:
    if not isinstance(request_bytes, bytes):
        raise TypeError("request_bytes must be bytes")
    if not request_bytes:
        raise ValueError("request_bytes cannot be empty")
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds size policy")
    try:
        decoded = request_bytes.decode("utf-8", errors="strict")
        return json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_parse_integer,
            parse_float=_reject_non_integer_number,
            parse_constant=_reject_non_integer_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request must be valid UTF-8 JSON") from exc


def canonical_json(request_bytes: bytes) -> bytes:
    parsed = parse_strict_json(request_bytes)
    return canonical_json_object(parsed)


def canonical_json_object(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _length_prefixed(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(part)) + part for part in parts)


def _field_digest(label: bytes, value: str) -> bytes:
    return hashlib.sha256(label + b"\x00" + value.encode("utf-8")).digest()


def _scope_digest(resource: str, action: str, deployment_id: str) -> bytes:
    return hashlib.sha256(
        b"scope-v1\x00"
        + _length_prefixed(
            resource.encode("utf-8"),
            action.encode("utf-8"),
            deployment_id.encode("utf-8"),
        )
    ).digest()


def _state_to_blob(state: int) -> bytes:
    unpack_state(state)
    return state.to_bytes(8, "big")


def _state_from_blob(blob: bytes) -> int:
    if not isinstance(blob, bytes) or len(blob) != 8:
        raise ValueError("invalid packed-state database encoding")
    return int.from_bytes(blob, "big")


def _uint64_to_blob(value: int, name: str) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= UINT64_MAX:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")
    return value.to_bytes(8, "big")


def _uint64_from_blob(blob: bytes, name: str) -> int:
    if not isinstance(blob, bytes) or len(blob) != 8:
        raise ValueError(f"invalid {name} database encoding")
    return int.from_bytes(blob, "big")


class Ed25519KeyRing:
    """Thread-safe key lifecycle with zeroization and cross-process database-backed status synchronization."""

    def __init__(
        self,
        purpose: KeyPurpose = KeyPurpose.CREDENTIAL_SIGNING,
        database: AuthorizationDatabase | None = None,
    ) -> None:
        if not isinstance(purpose, KeyPurpose):
            raise TypeError("purpose must be a KeyPurpose enum")
        self.purpose = purpose
        self.database = database
        self._records: dict[bytes, KeyRecord] = {}
        self._lock = threading.RLock()

    def generate(self, issuer: str, key_id: bytes | None = None) -> bytes:
        resolved = key_id or secrets.token_bytes(KEY_ID_SIZE)
        issuer_digest = _field_digest(
            b"issuer-v1",
            normalize_context(issuer, "issuer"),
        )
        private_key = Ed25519PrivateKey.generate()
        self._register(
            resolved,
            private_key.public_key(),
            private_key,
            KeyStatus.ACTIVE,
            issuer_digest,
        )
        return resolved

    def register_public(
        self,
        key_id: bytes,
        public_key_bytes: bytes,
        issuer: str,
        status: KeyStatus = KeyStatus.VERIFY_ONLY,
    ) -> None:
        if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
            raise TypeError("public_key_bytes must contain 32 bytes")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        issuer_digest = _field_digest(
            b"issuer-v1",
            normalize_context(issuer, "issuer"),
        )
        self._register(key_id, public_key, None, status, issuer_digest)

    def register_private(
        self,
        key_id: bytes,
        private_key_bytes: bytes,
        issuer: str,
        status: KeyStatus = KeyStatus.ACTIVE,
    ) -> None:
        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise TypeError("private_key_bytes must contain 32 bytes")
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        issuer_digest = _field_digest(
            b"issuer-v1",
            normalize_context(issuer, "issuer"),
        )
        self._register(key_id, private_key.public_key(), private_key, status, issuer_digest)

    def register_private_encrypted(
        self,
        key_id: bytes,
        encrypted_pem: bytes,
        passphrase: bytes,
        issuer: str,
        requested_status: KeyStatus = KeyStatus.ACTIVE,
    ) -> None:
        if not isinstance(encrypted_pem, bytes) or not encrypted_pem:
            raise TypeError("encrypted_pem must be non-empty bytes")
        if not isinstance(passphrase, bytes) or not passphrase:
            raise TypeError("passphrase must be non-empty bytes")
        private_key = serialization.load_pem_private_key(encrypted_pem, password=passphrase)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("key in PEM must be Ed25519PrivateKey")
        issuer_digest = _field_digest(
            b"issuer-v1",
            normalize_context(issuer, "issuer"),
        )
        
        # Consult persistent database registry to prevent reactivating rotated/retired keys
        effective_status = requested_status
        if self.database is not None:
            db_status = self.database.get_persisted_key_status(key_id)
            if db_status is not None:
                if db_status in (KeyStatus.VERIFY_ONLY, KeyStatus.RETIRED) and requested_status is KeyStatus.ACTIVE:
                    raise ValueError(f"cannot reactivate rotated/retired key (persisted status: {db_status.value})")
                effective_status = db_status

        self._register(key_id, private_key.public_key(), private_key, effective_status, issuer_digest)

    def _register(
        self,
        key_id: bytes,
        public_key: Ed25519PublicKey,
        private_key: Ed25519PrivateKey | None,
        status: KeyStatus,
        issuer_digest: bytes,
    ) -> None:
        if not isinstance(key_id, bytes) or len(key_id) != KEY_ID_SIZE:
            raise TypeError(f"key_id must contain {KEY_ID_SIZE} bytes")
        if not isinstance(status, KeyStatus):
            raise TypeError("status must be a KeyStatus")
        if not isinstance(issuer_digest, bytes) or len(issuer_digest) != SHA256_SIZE:
            raise ValueError("issuer_digest must contain 32 bytes")
        with self._lock:
            if key_id in self._records:
                raise ValueError("key-id collision")

            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # Persist key status into database BEFORE mutating in-memory dictionary
            effective_status = status
            if self.database is not None:
                existing_st = self.database.get_persisted_key_status(key_id)
                if existing_st is None:
                    self.database.persist_key_record(key_id, pub_bytes, self.purpose, issuer_digest, status)
                else:
                    effective_status = existing_st
            
            effective_priv = private_key if effective_status is KeyStatus.ACTIVE else None

            self._records[key_id] = KeyRecord(
                public_key,
                effective_priv,
                effective_status,
                self.purpose,
                issuer_digest,
            )

    def export_public(self, key_id: bytes) -> bytes:
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                raise KeyError("unknown key")
            return record.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

    def export_private_encrypted(self, key_id: bytes, passphrase: bytes) -> bytes:
        if not isinstance(passphrase, bytes) or not passphrase:
            raise ValueError("passphrase must be non-empty bytes")
        with self._lock:
            record = self._records.get(key_id)
            if record is None or record.private_key is None:
                raise KeyError("private key material unavailable or zeroized")
            if record.status is not KeyStatus.ACTIVE:
                raise ValueError("cannot export private material for non-ACTIVE key")
            return record.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )

    def transition(self, key_id: bytes, new_status: KeyStatus) -> None:
        if not isinstance(new_status, KeyStatus):
            raise TypeError("new_status must be a KeyStatus")
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                raise KeyError("unknown key")
            if new_status not in ALLOWED_KEY_TRANSITIONS[record.status]:
                raise ValueError(f"invalid key transition: {record.status} -> {new_status}")

            pub_bytes = record.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # Synchronize status transition to persistent database FIRST
            if self.database is not None:
                self.database.persist_key_record(key_id, pub_bytes, self.purpose, record.issuer_digest, new_status)

            effective_priv = record.private_key if new_status is KeyStatus.ACTIVE else None

            self._records[key_id] = KeyRecord(
                record.public_key,
                effective_priv,
                new_status,
                record.purpose,
                record.issuer_digest,
            )

    def sign(self, key_id: bytes, payload: bytes, issuer_digest: bytes) -> bytes:
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                raise ValueError("key is not active for issuance")

            # Cross-process live database status check
            if self.database is not None:
                db_status = self.database.get_persisted_key_status(key_id)
                if db_status is None:
                    raise ValueError("key is not registered in database")
                if db_status is not KeyStatus.ACTIVE:
                    # Update local memory status and zeroize private key reference
                    self._records[key_id] = KeyRecord(
                        record.public_key, None, db_status, record.purpose, record.issuer_digest
                    )
                    raise ValueError(f"key is no longer active in database (persisted status: {db_status.value})")

            if record.status is not KeyStatus.ACTIVE:
                raise ValueError("key is not active for issuance")
            if record.private_key is None:
                raise ValueError("private signing material is unavailable or zeroized")
            if not hmac.compare_digest(record.issuer_digest, issuer_digest):
                raise ValueError("signing key is not bound to this issuer")
            return record.private_key.sign(payload)

    def verify(
        self,
        key_id: bytes,
        payload: bytes,
        signature: bytes,
        issuer_digest: bytes,
    ) -> None:
        with self._lock:
            record = self._records.get(key_id)

            # ALWAYS sync with database if database is present to detect process-wide key retirement/deletion
            if self.database is not None:
                db_record = self.database.get_key_record_full(key_id)
                if db_record is None or db_record["status"] == KeyStatus.RETIRED.value:
                    if record is not None:
                        self._records[key_id] = KeyRecord(
                            record.public_key, None, KeyStatus.RETIRED, record.purpose, record.issuer_digest
                        )
                    raise AuthorizationRejected(AuthStatus.REJECT_UNKNOWN_KEY)
                
                db_st = KeyStatus(db_record["status"])
                if record is None:
                    pub_key = Ed25519PublicKey.from_public_bytes(db_record["public_key"])
                    self._records[key_id] = KeyRecord(
                        pub_key, None, db_st, KeyPurpose(db_record["purpose"]), db_record["issuer_digest"]
                    )
                    record = self._records[key_id]
                else:
                    # Update cached record status if DB has progressed to VERIFY_ONLY or RETIRED
                    if record.status != db_st:
                        self._records[key_id] = KeyRecord(
                            record.public_key, record.private_key if db_st is KeyStatus.ACTIVE else None,
                            db_st, record.purpose, record.issuer_digest
                        )
                        record = self._records[key_id]

            if record is None or record.status is KeyStatus.RETIRED:
                raise AuthorizationRejected(AuthStatus.REJECT_UNKNOWN_KEY)
            try:
                record.public_key.verify(signature, payload)
            except InvalidSignature as exc:
                raise AuthorizationRejected(AuthStatus.REJECT_INVALID_SIGNATURE) from exc
            if not hmac.compare_digest(record.issuer_digest, issuer_digest):
                raise AuthorizationRejected(AuthStatus.REJECT_ISSUER_MISMATCH)


class CredentialCodec:
    """Issue and statelessly verify fixed-layout Ed25519 credentials."""

    def __init__(
        self,
        keyring: Ed25519KeyRing,
        principal_binding_key: bytes,
        deployment_id: str,
    ) -> None:
        if not isinstance(principal_binding_key, bytes) or len(principal_binding_key) < 32:
            raise ValueError("principal_binding_key must contain at least 32 bytes")
        if keyring.purpose is not KeyPurpose.CREDENTIAL_SIGNING:
            raise ValueError("credential codec keyring must have KeyPurpose.CREDENTIAL_SIGNING")
        self._keyring = keyring
        self._principal_binding_key = bytes(principal_binding_key)
        self._deployment_id = normalize_context(deployment_id, "deployment_id")

    def _principal_digest(self, principal: str) -> bytes:
        return hmac.digest(
            self._principal_binding_key,
            b"principal-v1\x00" + principal.encode("utf-8"),
            hashlib.sha256,
        )

    def issue(
        self,
        *,
        key_id: bytes,
        packed_state: int,
        issuer_epoch: int,
        issued_at: int,
        not_before: int,
        expires_at: int,
        issuer: str,
        principal_id: str,
        audience: str,
        resource: str,
        action: str,
        request_bytes: bytes,
        policy_digest: bytes,
        credential_id: bytes | None = None,
    ) -> bytes:
        if not isinstance(key_id, bytes) or len(key_id) != KEY_ID_SIZE:
            raise ValueError(f"key_id must contain {KEY_ID_SIZE} bytes")
        unpack_state(packed_state)
        validate_time_window(issued_at, not_before, expires_at)
        _uint64_to_blob(issuer_epoch, "issuer_epoch")
        if not isinstance(policy_digest, bytes) or len(policy_digest) != SHA256_SIZE:
            raise ValueError("policy_digest must contain 32 bytes")
        resolved_credential_id = credential_id or secrets.token_bytes(CREDENTIAL_ID_SIZE)
        if not isinstance(resolved_credential_id, bytes) or len(resolved_credential_id) != CREDENTIAL_ID_SIZE:
            raise ValueError(f"credential_id must contain {CREDENTIAL_ID_SIZE} bytes")
        normalized_issuer = normalize_context(issuer, "issuer")
        normalized_principal = normalize_context(principal_id, "principal_id")
        normalized_audience = normalize_context(audience, "audience")
        normalized_resource = normalize_context(resource, "resource")
        normalized_action = normalize_context(action, "action")
        request_digest = hashlib.sha256(canonical_json(request_bytes)).digest()
        issuer_digest = _field_digest(b"issuer-v1", normalized_issuer)
        payload = CREDENTIAL_PAYLOAD.pack(
            PROTOCOL_VERSION,
            key_id,
            issuer_epoch,
            packed_state,
            issued_at,
            not_before,
            expires_at,
            resolved_credential_id,
            issuer_digest,
            self._principal_digest(normalized_principal),
            _field_digest(b"audience-v1", normalized_audience),
            _scope_digest(normalized_resource, normalized_action, self._deployment_id),
            request_digest,
            policy_digest,
        )
        signature = self._keyring.sign(key_id, payload, issuer_digest)
        return payload + signature

    def verify(
        self,
        token: bytes,
        *,
        current_time: int,
        expected_issuer: str,
        expected_principal_id: str,
        expected_audience: str,
        expected_resource: str,
        expected_action: str,
        expected_request_bytes: bytes,
    ) -> CredentialClaims:
        try:
            validate_timestamp(current_time, "current_time")
        except (TypeError, ValueError) as exc:
            raise AuthorizationRejected(AuthStatus.REJECT_INVALID_CURRENT_TIME) from exc
        if not isinstance(token, bytes) or len(token) != EXPECTED_TOKEN_SIZE:
            raise AuthorizationRejected(AuthStatus.REJECT_MALFORMED_PAYLOAD)
        payload = token[:EXPECTED_PAYLOAD_SIZE]
        signature = token[EXPECTED_PAYLOAD_SIZE:]
        unpacked = CREDENTIAL_PAYLOAD.unpack(payload)
        (
            version,
            key_id,
            issuer_epoch,
            packed_state,
            issued_at,
            not_before,
            expires_at,
            credential_id,
            issuer_digest,
            principal_digest,
            audience_digest,
            scope_digest,
            request_digest,
            policy_digest,
        ) = unpacked
        self._keyring.verify(key_id, payload, signature, issuer_digest)
        if version != PROTOCOL_VERSION:
            raise AuthorizationRejected(AuthStatus.REJECT_VERSION_MISMATCH)
        if not issued_at <= not_before < expires_at:
            raise AuthorizationRejected(AuthStatus.REJECT_INVALID_TIME_WINDOW)
        if expires_at - issued_at > MAX_CREDENTIAL_LIFETIME_SECONDS:
            raise AuthorizationRejected(AuthStatus.REJECT_LIFETIME_EXCEEDED)
        if issued_at > current_time + MAX_CLOCK_SKEW_SECONDS:
            raise AuthorizationRejected(AuthStatus.REJECT_ISSUED_IN_FUTURE)
        if current_time + MAX_CLOCK_SKEW_SECONDS < not_before:
            raise AuthorizationRejected(AuthStatus.REJECT_NOT_YET_VALID)
        if current_time >= expires_at:
            raise AuthorizationRejected(AuthStatus.REJECT_EXPIRED)
        normalized_issuer = normalize_context(expected_issuer, "expected_issuer")
        normalized_principal = normalize_context(expected_principal_id, "expected_principal_id")
        normalized_audience = normalize_context(expected_audience, "expected_audience")
        normalized_resource = normalize_context(expected_resource, "expected_resource")
        normalized_action = normalize_context(expected_action, "expected_action")
        expected_values = (
            (issuer_digest, _field_digest(b"issuer-v1", normalized_issuer), AuthStatus.REJECT_ISSUER_MISMATCH),
            (principal_digest, self._principal_digest(normalized_principal), AuthStatus.REJECT_PRINCIPAL_MISMATCH),
            (audience_digest, _field_digest(b"audience-v1", normalized_audience), AuthStatus.REJECT_AUDIENCE_MISMATCH),
            (
                scope_digest,
                _scope_digest(normalized_resource, normalized_action, self._deployment_id),
                AuthStatus.REJECT_SCOPE_MISMATCH,
            ),
            (
                request_digest,
                hashlib.sha256(canonical_json(expected_request_bytes)).digest(),
                AuthStatus.REJECT_REQUEST_DIGEST_MISMATCH,
            ),
        )
        for actual, expected, status in expected_values:
            if not hmac.compare_digest(actual, expected):
                raise AuthorizationRejected(status)
        return CredentialClaims(
            key_id=key_id,
            issuer_epoch=issuer_epoch,
            packed_state=packed_state,
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            credential_id=credential_id,
            issuer_digest=issuer_digest,
            principal_digest=principal_digest,
            audience_digest=audience_digest,
            scope_digest=scope_digest,
            request_digest=request_digest,
            policy_digest=policy_digest,
            token_digest=hashlib.sha256(token).digest(),
            normalized_principal=normalized_principal,
        )


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    packed_state BLOB NOT NULL CHECK(length(packed_state) = 8)
) STRICT;

CREATE TABLE IF NOT EXISTS issuers (
    issuer_digest BLOB PRIMARY KEY CHECK(length(issuer_digest) = 32),
    issuer_epoch BLOB NOT NULL CHECK(length(issuer_epoch) = 8)
) STRICT;

CREATE TABLE IF NOT EXISTS policies (
    policy_name TEXT PRIMARY KEY,
    policy_digest BLOB NOT NULL CHECK(length(policy_digest) = 32)
) STRICT;

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    balance_minor INTEGER NOT NULL CHECK(
        typeof(balance_minor) = 'integer'
        AND balance_minor >= 0
        AND balance_minor <= 9223372036854775807
    ),
    version INTEGER NOT NULL DEFAULT 0 CHECK(typeof(version) = 'integer' AND version >= 0)
) STRICT;

CREATE TABLE IF NOT EXISTS key_records (
    key_id BLOB PRIMARY KEY CHECK(length(key_id) = 16),
    public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
    purpose TEXT NOT NULL CHECK(purpose IN ('credential_signing', 'receipt_signing')),
    issuer_digest BLOB NOT NULL CHECK(length(issuer_digest) = 32),
    status TEXT NOT NULL CHECK(status IN ('active', 'verify_only', 'retired'))
) STRICT;

CREATE TABLE IF NOT EXISTS credential_results (
    credential_id BLOB PRIMARY KEY CHECK(length(credential_id) = 16),
    token_digest BLOB NOT NULL CHECK(length(token_digest) = 32),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    result_payload BLOB NOT NULL,
    result_digest BLOB NOT NULL CHECK(length(result_digest) = 32),
    receipt_signature BLOB CHECK(receipt_signature IS NULL OR length(receipt_signature) = 64),
    receipt_key_id BLOB CHECK(receipt_key_id IS NULL OR length(receipt_key_id) = 16),
    principal_digest BLOB NOT NULL CHECK(length(principal_digest) = 32),
    committed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32),
    event_hash BLOB NOT NULL CHECK(length(event_hash) = 32),
    payload BLOB NOT NULL
) STRICT;

CREATE TRIGGER IF NOT EXISTS key_records_status_guard
BEFORE UPDATE ON key_records
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN OLD.status = 'verify_only' AND NEW.status = 'active'
            THEN RAISE(ABORT, 'cannot reactivate verify_only key')
        WHEN OLD.status = 'retired' AND NEW.status != 'retired'
            THEN RAISE(ABORT, 'cannot reactivate retired key')
        WHEN OLD.public_key != NEW.public_key OR OLD.purpose != NEW.purpose OR OLD.issuer_digest != NEW.issuer_digest
            THEN RAISE(ABORT, 'immutable key metadata violation')
    END;
END;

CREATE TRIGGER IF NOT EXISTS key_records_delete_guard
BEFORE DELETE ON key_records
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'deletion of key_records is strictly forbidden');
END;
"""


class AuthorizationDatabase:
    """SQLite-backed linearizable authority and protected ledger store."""

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5_000) -> None:
        self.path = str(path)
        self.busy_timeout_ms = busy_timeout_ms
        connection = self.connect()
        try:
            connection.executescript(SCHEMA_SQL)
            self._migrate_schema(connection)
        finally:
            connection.close()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            timeout=self.busy_timeout_ms / 1000,
        )
        connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _migrate_table_to_strict(self, connection: sqlite3.Connection, table_name: str, create_sql: str) -> None:
        sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
        if sql_row and "STRICT" not in sql_row[0]:
            temp_name = f"{table_name}_v26_strict"
            create_temp = create_sql.replace(f"CREATE TABLE IF NOT EXISTS {table_name}", f"CREATE TABLE {temp_name}")
            create_temp = create_temp.replace(f"CREATE TABLE {table_name}", f"CREATE TABLE {temp_name}")
            connection.execute(create_temp)
            connection.execute(f"INSERT INTO {temp_name} SELECT * FROM {table_name};")
            connection.execute(f"DROP TABLE {table_name};")
            connection.execute(f"ALTER TABLE {temp_name} RENAME TO {table_name};")

    def _migrate_schema(self, connection: sqlite3.Connection) -> None:
        """MANDATORY MIGRATION: Preserves replay rows, validates legacy data integrity, updates all tables and triggers to v26 STRICT."""
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version < 26:
            connection.execute("BEGIN EXCLUSIVE")
            try:
                # 1. ACCOUNT INTEGRITY MIGRATION WITH STRICT ZERO-DATA-LOSS CHECK
                account_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='accounts'").fetchone()
                if account_sql and "STRICT" not in account_sql[0]:
                    src_cnt = connection.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
                    invalid_cnt = connection.execute(
                        "SELECT COUNT(*) FROM accounts WHERE typeof(balance_minor) != 'integer' OR balance_minor < 0 OR balance_minor > 9223372036854775807 OR typeof(version) != 'integer' OR version < 0"
                    ).fetchone()[0]

                    if invalid_cnt > 0:
                        raise MigrationError(f"legacy accounts contain {invalid_cnt} invalid/corrupt rows; reconciliation required")

                    connection.execute("""
                        CREATE TABLE accounts_v26 (
                            account_id TEXT PRIMARY KEY,
                            balance_minor INTEGER NOT NULL CHECK(
                                typeof(balance_minor) = 'integer'
                                AND balance_minor BETWEEN 0 AND 9223372036854775807
                            ),
                            version INTEGER NOT NULL CHECK(typeof(version) = 'integer' AND version >= 0)
                        ) STRICT;
                    """)
                    connection.execute("INSERT INTO accounts_v26 SELECT account_id, balance_minor, version FROM accounts;")
                    mig_cnt = connection.execute("SELECT COUNT(*) FROM accounts_v26").fetchone()[0]

                    if mig_cnt != src_cnt:  # pragma: no cover
                        raise MigrationError(f"account migration row count mismatch: source={src_cnt}, migrated={mig_cnt}")

                    connection.execute("DROP TABLE accounts;")
                    connection.execute("ALTER TABLE accounts_v26 RENAME TO accounts;")

                # 2. KEY RECORDS V26 REBUILD WITH UNIQUE(public_key) AND TRIGGERS
                kr_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='key_records'").fetchone()
                if kr_sql and ("UNIQUE" not in kr_sql[0] or "CHECK(purpose IN" not in kr_sql[0]):
                    connection.execute("""
                        CREATE TABLE key_records_v26 (
                            key_id BLOB PRIMARY KEY CHECK(length(key_id) = 16),
                            public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
                            purpose TEXT NOT NULL CHECK(purpose IN ('credential_signing', 'receipt_signing')),
                            issuer_digest BLOB NOT NULL CHECK(length(issuer_digest) = 32),
                            status TEXT NOT NULL CHECK(status IN ('active', 'verify_only', 'retired'))
                        ) STRICT;
                    """)
                    connection.execute("INSERT INTO key_records_v26 SELECT * FROM key_records;")
                    connection.execute("DROP TABLE key_records;")
                    connection.execute("ALTER TABLE key_records_v26 RENAME TO key_records;")

                # Ensure triggers exist
                connection.execute("""
                    CREATE TRIGGER IF NOT EXISTS key_records_status_guard
                    BEFORE UPDATE ON key_records
                    FOR EACH ROW
                    BEGIN
                        SELECT CASE
                            WHEN OLD.status = 'verify_only' AND NEW.status = 'active'
                                THEN RAISE(ABORT, 'cannot reactivate verify_only key')
                            WHEN OLD.status = 'retired' AND NEW.status != 'retired'
                                THEN RAISE(ABORT, 'cannot reactivate retired key')
                            WHEN OLD.public_key != NEW.public_key OR OLD.purpose != NEW.purpose OR OLD.issuer_digest != NEW.issuer_digest
                                THEN RAISE(ABORT, 'immutable key metadata violation')
                        END;
                    END;
                """)
                connection.execute("""
                    CREATE TRIGGER IF NOT EXISTS key_records_delete_guard
                    BEFORE DELETE ON key_records
                    FOR EACH ROW
                    BEGIN
                        SELECT RAISE(ABORT, 'deletion of key_records is strictly forbidden');
                    END;
                """)

                # 3. CREDENTIAL RESULTS REPLAY HISTORY PRESERVATION
                res_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='credential_results'").fetchone()
                cols = [c[1] for c in connection.execute("PRAGMA table_info(credential_results)").fetchall()]

                if "receipt_signature" not in cols or "receipt_key_id" not in cols or (res_sql and "STRICT" not in res_sql[0]):
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS credential_results_v26 (
                            credential_id BLOB PRIMARY KEY CHECK(length(credential_id) = 16),
                            token_digest BLOB NOT NULL CHECK(length(token_digest) = 32),
                            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                            result_payload BLOB NOT NULL,
                            result_digest BLOB NOT NULL CHECK(length(result_digest) = 32),
                            receipt_signature BLOB CHECK(receipt_signature IS NULL OR length(receipt_signature) = 64),
                            receipt_key_id BLOB CHECK(receipt_key_id IS NULL OR length(receipt_key_id) = 16),
                            principal_digest BLOB NOT NULL CHECK(length(principal_digest) = 32),
                            committed_at INTEGER NOT NULL,
                            expires_at INTEGER NOT NULL
                        ) STRICT;
                    """)
                    if "receipt_signature" in cols and "receipt_key_id" in cols:
                        connection.execute("INSERT INTO credential_results_v26 SELECT * FROM credential_results;")
                    elif "receipt_signature" in cols:
                        connection.execute("""
                            INSERT INTO credential_results_v26 (credential_id, token_digest, request_digest, result_payload, result_digest, receipt_signature, receipt_key_id, principal_digest, committed_at, expires_at)
                            SELECT credential_id, token_digest, request_digest, result_payload, result_digest, receipt_signature, NULL, principal_digest, committed_at, expires_at FROM credential_results;
                        """)
                    else:
                        connection.execute("""
                            INSERT INTO credential_results_v26 (credential_id, token_digest, request_digest, result_payload, result_digest, receipt_signature, receipt_key_id, principal_digest, committed_at, expires_at)
                            SELECT credential_id, token_digest, request_digest, result_payload, result_digest, NULL, NULL, principal_digest, committed_at, expires_at FROM credential_results;
                        """)
                    connection.execute("DROP TABLE credential_results;")
                    connection.execute("ALTER TABLE credential_results_v26 RENAME TO credential_results;")

                # 4. MIGRATE REMAINING TABLES TO STRICT
                self._migrate_table_to_strict(connection, "principals", "CREATE TABLE principals (principal_id TEXT PRIMARY KEY, packed_state BLOB NOT NULL CHECK(length(packed_state) = 8)) STRICT;")
                self._migrate_table_to_strict(connection, "issuers", "CREATE TABLE issuers (issuer_digest BLOB PRIMARY KEY CHECK(length(issuer_digest) = 32), issuer_epoch BLOB NOT NULL CHECK(length(issuer_epoch) = 8)) STRICT;")
                self._migrate_table_to_strict(connection, "policies", "CREATE TABLE policies (policy_name TEXT PRIMARY KEY, policy_digest BLOB NOT NULL CHECK(length(policy_digest) = 32)) STRICT;")
                self._migrate_table_to_strict(connection, "audit_events", "CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32), event_hash BLOB NOT NULL CHECK(length(event_hash) = 32), payload BLOB NOT NULL) STRICT;")

                connection.execute("PRAGMA user_version = 26;")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def persist_key_record(
        self,
        key_id: bytes,
        public_key: bytes,
        purpose: KeyPurpose,
        issuer_digest: bytes,
        status: KeyStatus,
    ) -> None:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT public_key, purpose, issuer_digest, status FROM key_records WHERE key_id = ?",
                (key_id,),
            ).fetchone()

            if existing is not None:
                old_pub, old_purpose, old_issuer, old_st_str = existing
                old_st = KeyStatus(old_st_str)

                # Verify immutability of public_key, purpose, and issuer_digest
                if not hmac.compare_digest(old_pub, public_key) or old_purpose != purpose.value or not hmac.compare_digest(old_issuer, issuer_digest):
                    raise ValueError("cannot alter immutable key metadata (public_key, purpose, issuer_digest) for existing key_id")

                if status not in ALLOWED_KEY_TRANSITIONS[old_st] and status != old_st:
                    raise ValueError(f"invalid persistent key transition in DB: {old_st.value} -> {status.value}")

            connection.execute(
                "INSERT INTO key_records(key_id, public_key, purpose, issuer_digest, status) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(key_id) DO UPDATE SET status = excluded.status",
                (key_id, public_key, purpose.value, issuer_digest, status.value),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_persisted_key_status(self, key_id: bytes) -> KeyStatus | None:
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT status FROM key_records WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            return KeyStatus(row[0]) if row is not None else None
        finally:
            connection.close()

    def get_key_record_full(self, key_id: bytes) -> dict[str, Any] | None:
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT public_key, purpose, issuer_digest, status FROM key_records WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "public_key": row[0],
                "purpose": row[1],
                "issuer_digest": row[2],
                "status": row[3],
            }
        finally:
            connection.close()

    def find_key_by_public_bytes(self, public_key_bytes: bytes) -> bytes | None:
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT key_id FROM key_records WHERE public_key = ?",
                (public_key_bytes,),
            ).fetchone()
            return row[0] if row is not None else None
        finally:
            connection.close()

    def initialize_principal(self, principal_id: str, packed_state: int) -> None:
        principal = normalize_context(principal_id, "principal_id")
        state_blob = _state_to_blob(packed_state)
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT packed_state FROM principals WHERE principal_id = ?",
                (principal,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO principals(principal_id, packed_state) VALUES(?, ?)",
                    (principal, state_blob),
                )
            elif not hmac.compare_digest(row[0], state_blob):
                raise ValueError("principal already exists with different authority state")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize_issuer(self, issuer: str, epoch: int = 0) -> None:
        normalized = normalize_context(issuer, "issuer")
        digest = _field_digest(b"issuer-v1", normalized)
        epoch_blob = _uint64_to_blob(epoch, "issuer_epoch")
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT issuer_epoch FROM issuers WHERE issuer_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO issuers(issuer_digest, issuer_epoch) VALUES(?, ?)",
                    (digest, epoch_blob),
                )
            elif not hmac.compare_digest(row[0], epoch_blob):
                raise ValueError("issuer already exists with different epoch")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def set_policy(self, policy_name: str, canonical_policy: bytes) -> bytes:
        name = normalize_context(policy_name, "policy_name")
        if not isinstance(canonical_policy, bytes) or not canonical_policy:
            raise ValueError("canonical_policy must be non-empty bytes")
        digest = hashlib.sha256(canonical_policy).digest()
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO policies(policy_name, policy_digest) VALUES(?, ?) "
                "ON CONFLICT(policy_name) DO UPDATE SET policy_digest = excluded.policy_digest",
                (name, digest),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return digest

    def create_account(self, account_id: str, balance_minor: int) -> None:
        account = normalize_context(account_id, "account_id")
        if not isinstance(balance_minor, int) or isinstance(balance_minor, bool):
            raise TypeError("balance_minor must be an integer")
        if not 0 <= balance_minor <= 9223372036854775807:
            raise ValueError("balance_minor is outside the supported range")
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT balance_minor FROM accounts WHERE account_id = ?",
                (account,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO accounts(account_id, balance_minor) VALUES(?, ?)",
                    (account, balance_minor),
                )
            elif row[0] != balance_minor:
                raise ValueError("account already exists with a different balance")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def issuance_snapshot(
        self,
        principal_id: str,
        issuer: str,
        policy_name: str,
    ) -> IssuanceSnapshot:
        principal = normalize_context(principal_id, "principal_id")
        issuer_digest = _field_digest(b"issuer-v1", normalize_context(issuer, "issuer"))
        policy = normalize_context(policy_name, "policy_name")
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            state_row = connection.execute(
                "SELECT packed_state FROM principals WHERE principal_id = ?",
                (principal,),
            ).fetchone()
            issuer_row = connection.execute(
                "SELECT issuer_epoch FROM issuers WHERE issuer_digest = ?",
                (issuer_digest,),
            ).fetchone()
            policy_row = connection.execute(
                "SELECT policy_digest FROM policies WHERE policy_name = ?",
                (policy,),
            ).fetchone()
            if state_row is None:
                raise LookupError("unknown principal")
            if issuer_row is None:
                raise LookupError("unknown issuer")
            if policy_row is None:
                raise LookupError("unknown policy")
            snapshot = IssuanceSnapshot(
                packed_state=_state_from_blob(state_row[0]),
                issuer_epoch=_uint64_from_blob(issuer_row[0], "issuer_epoch"),
                policy_digest=policy_row[0],
            )
            connection.commit()
            return snapshot
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def bump_principal_epoch(self, principal_id: str, field: str) -> int:
        principal = normalize_context(principal_id, "principal_id")
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT packed_state FROM principals WHERE principal_id = ?",
                (principal,),
            ).fetchone()
            if row is None:
                raise LookupError("unknown principal")
            new_state = advance_epoch(_state_from_blob(row[0]), field)
            connection.execute(
                "UPDATE principals SET packed_state = ? WHERE principal_id = ?",
                (_state_to_blob(new_state), principal),
            )
            connection.commit()
            return new_state
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def bump_issuer_epoch(self, issuer: str) -> int:
        digest = _field_digest(b"issuer-v1", normalize_context(issuer, "issuer"))
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT issuer_epoch FROM issuers WHERE issuer_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise LookupError("unknown issuer")
            current = _uint64_from_blob(row[0], "issuer_epoch")
            if current >= UINT64_MAX:
                raise OverflowError("issuer epoch exhausted; issuer rekey required")
            updated = current + 1
            connection.execute(
                "UPDATE issuers SET issuer_epoch = ? WHERE issuer_digest = ?",
                (_uint64_to_blob(updated, "issuer_epoch"), digest),
            )
            connection.commit()
            return updated
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def balance(self, account_id: str) -> int:
        account = normalize_context(account_id, "account_id")
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT balance_minor FROM accounts WHERE account_id = ?",
                (account,),
            ).fetchone()
            if row is None:
                raise LookupError("unknown account")
            return int(row[0])
        finally:
            connection.close()

    def purge_expired_receipts(self, current_time: int) -> int:
        """Purges expired rows from credential_results where expires_at <= current_time."""
        validate_timestamp(current_time, "current_time")
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM credential_results WHERE expires_at <= ?",
                (current_time,),
            )
            count = cursor.rowcount
            connection.commit()
            return count
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def can_retire_key(self, key_id: bytes, current_time: int) -> bool:
        """Atomic safe-to-retire check: Returns True iff zero unexpired receipts exist for key_id."""
        validate_timestamp(current_time, "current_time")
        if not isinstance(key_id, bytes) or len(key_id) != KEY_ID_SIZE:
            raise TypeError(f"key_id must contain {KEY_ID_SIZE} bytes")
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM credential_results WHERE receipt_key_id = ? AND expires_at > ?",
                (key_id, current_time),
            ).fetchone()
            return row[0] == 0
        finally:
            connection.close()

    def append_audit_log(
        self,
        connection: sqlite3.Connection,
        audit_key: bytes,
        event_dict: Mapping[str, Any],
    ) -> bytes:
        payload = canonical_json_object(event_dict)
        if len(payload) > MAX_AUDIT_PAYLOAD_BYTES:
            raise ValueError("audit log payload exceeds maximum size")
        last_row = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = last_row[0] if last_row is not None else b"\x00" * SHA256_SIZE
        event_hash = hmac.digest(audit_key, previous_hash + payload, hashlib.sha256)
        connection.execute(
            "INSERT INTO audit_events(previous_hash, event_hash, payload) VALUES(?, ?, ?)",
            (previous_hash, event_hash, payload),
        )
        return event_hash

    def verify_audit_log(
        self,
        audit_key: bytes,
        trusted_checkpoint: tuple[int, bytes] | None = None,
    ) -> tuple[bool, int, bytes]:
        """Strictly verifies audit log chain. Genesis checkpoint MUST be (0, 32_zero_bytes)."""
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise ValueError("audit_key must contain at least 32 bytes")

        if trusted_checkpoint is not None:
            if not isinstance(trusted_checkpoint, tuple) or len(trusted_checkpoint) != 2:
                return (False, 0, b"\x00" * SHA256_SIZE)
            cp_seq, cp_hash = trusted_checkpoint
            if not isinstance(cp_seq, int) or isinstance(cp_seq, bool) or cp_seq < 0:
                return (False, 0, b"\x00" * SHA256_SIZE)
            if not isinstance(cp_hash, bytes) or len(cp_hash) != 32:
                return (False, 0, b"\x00" * SHA256_SIZE)

        connection = self.connect()
        try:
            rows = connection.execute(
                "SELECT sequence, previous_hash, event_hash, payload FROM audit_events ORDER BY sequence ASC"
            ).fetchall()
            
            if not rows:
                if trusted_checkpoint is not None:
                    cp_seq, cp_hash = trusted_checkpoint
                    if cp_seq != 0 or cp_hash != b"\x00" * SHA256_SIZE:
                        return (False, 0, b"\x00" * SHA256_SIZE)
                return (True, 0, b"\x00" * SHA256_SIZE)
            
            expected_prev = b"\x00" * SHA256_SIZE
            count = 0
            latest_hash = b"\x00" * SHA256_SIZE
            cp_verified = False if trusted_checkpoint is not None else True

            if trusted_checkpoint is not None:
                cp_seq, cp_hash = trusted_checkpoint
                if cp_seq == 0 and cp_hash == b"\x00" * SHA256_SIZE:
                    cp_verified = True

            for seq, prev_hash, ev_hash, payload in rows:
                if not hmac.compare_digest(prev_hash, expected_prev):
                    return (False, count, latest_hash)
                computed_ev_hash = hmac.digest(audit_key, prev_hash + payload, hashlib.sha256)
                if not hmac.compare_digest(ev_hash, computed_ev_hash):
                    return (False, count, latest_hash)
                
                expected_prev = ev_hash
                latest_hash = ev_hash
                count += 1

                if trusted_checkpoint is not None and not cp_verified:
                    cp_seq, cp_hash = trusted_checkpoint
                    if seq == cp_seq:
                        if not hmac.compare_digest(ev_hash, cp_hash):
                            return (False, count, latest_hash)
                        cp_verified = True

            if not cp_verified:
                return (False, count, latest_hash)

            return (True, count, latest_hash)
        finally:
            connection.close()


class LinearizableEngine:
    """Executes authorization, ledger mutations, and audit logging in one SQLite transaction."""

    def __init__(
        self,
        database: AuthorizationDatabase,
        codec: CredentialCodec,
        audit_key: bytes,
        receipt_keyring: Ed25519KeyRing | None = None,
        receipt_key_id: bytes | None = None,
    ) -> None:
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise ValueError("audit_key must contain at least 32 bytes")
        if receipt_keyring is None or receipt_key_id is None:
            raise RuntimeError("dedicated receipt signer is required")
        if receipt_keyring is codec._keyring:
            raise ValueError("receipt_keyring must be distinct from credential-signing keyring")
        if receipt_keyring.purpose is not KeyPurpose.RECEIPT_SIGNING:
            raise ValueError("receipt keyring must have KeyPurpose.RECEIPT_SIGNING")

        receipt_pub_bytes = receipt_keyring.export_public(receipt_key_id)
        for cred_k_id in codec._keyring._records:
            cred_pub_bytes = codec._keyring.export_public(cred_k_id)
            if hmac.compare_digest(receipt_pub_bytes, cred_pub_bytes):
                raise ValueError("cryptographic key separation violation: receipt key cannot match credential signing key")

        try:
            dummy_payload = b"init_check"
            dummy_issuer = codec._principal_binding_key[:32]
            receipt_keyring.sign(receipt_key_id, dummy_payload, dummy_issuer)
        except ValueError as exc:
            if "signing key is not bound" not in str(exc):
                raise ValueError(f"receipt_key_id is invalid or not active for signing: {exc}") from exc

        self.database = database
        self.codec = codec
        self.audit_key = bytes(audit_key)
        self.receipt_keyring = receipt_keyring
        self.receipt_key_id = bytes(receipt_key_id)

    def execute_transfer(
        self,
        token: bytes,
        *,
        current_time: int,
        expected_issuer: str,
        expected_principal_id: str,
        expected_audience: str,
        expected_resource: str,
        expected_action: str,
        expected_request_bytes: bytes,
        expected_policy_name: str,
        crash_point: str = "",
    ) -> AuthorizationResult:
        claims = self.codec.verify(
            token,
            current_time=current_time,
            expected_issuer=expected_issuer,
            expected_principal_id=expected_principal_id,
            expected_audience=expected_audience,
            expected_resource=expected_resource,
            expected_action=expected_action,
            expected_request_bytes=expected_request_bytes,
        )
        parsed_request = parse_strict_json(expected_request_bytes)
        if not isinstance(parsed_request, dict):
            raise AuthorizationRejected(AuthStatus.REJECT_INVALID_REQUEST)

        expected_schema_keys = {"action", "amount_minor", "destination_account", "source_account"}
        if set(parsed_request.keys()) != expected_schema_keys:
            raise AuthorizationRejected(AuthStatus.REJECT_INVALID_REQUEST)

        if parsed_request["action"] != "transfer":
            raise AuthorizationRejected(AuthStatus.REJECT_INVALID_REQUEST)

        source_account = normalize_context(parsed_request["source_account"], "source_account")
        destination_account = normalize_context(parsed_request["destination_account"], "destination_account")
        amount_minor = parsed_request["amount_minor"]

        if not isinstance(amount_minor, int) or isinstance(amount_minor, bool) or amount_minor <= 0:
            raise AuthorizationRejected(AuthStatus.REJECT_INVALID_REQUEST)

        if source_account == destination_account:
            raise AuthorizationRejected(AuthStatus.REJECT_INVALID_REQUEST)

        connection = self.database.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if crash_point == "after_begin":
                raise RuntimeError("crash: after_begin")

            existing = connection.execute(
                "SELECT token_digest, request_digest, principal_digest, result_payload, result_digest, receipt_signature, receipt_key_id FROM credential_results "
                "WHERE credential_id = ?",
                (claims.credential_id,),
            ).fetchone()
            if existing is not None:
                stored_tok_digest, stored_req_digest, stored_prin_digest, result_payload_blob, stored_res_digest, stored_receipt_sig, stored_r_key_id = existing

                if not hmac.compare_digest(stored_tok_digest, claims.token_digest):
                    raise AuthorizationRejected(AuthStatus.REJECT_CREDENTIAL_CONFLICT)
                if not hmac.compare_digest(stored_prin_digest, claims.principal_digest):
                    raise AuthorizationRejected(AuthStatus.REJECT_CREDENTIAL_CONFLICT)
                if not hmac.compare_digest(stored_req_digest, claims.request_digest):
                    raise AuthorizationRejected(AuthStatus.REJECT_CREDENTIAL_CONFLICT)

                if stored_receipt_sig is None or stored_r_key_id is None:
                    raise AuthorizationRejected(AuthStatus.REJECT_LEGACY_RESULT_UNVERIFIED)

                calculated_res_digest = hashlib.sha256(result_payload_blob).digest()
                if not hmac.compare_digest(stored_res_digest, calculated_res_digest):
                    raise AuthorizationRejected(AuthStatus.REJECT_RESULT_TAMPERED)

                receipt_payload = (
                    claims.credential_id
                    + claims.token_digest
                    + claims.request_digest
                    + calculated_res_digest
                )
                try:
                    self.receipt_keyring.verify(stored_r_key_id, receipt_payload, stored_receipt_sig, claims.issuer_digest)
                except Exception:
                    raise AuthorizationRejected(AuthStatus.REJECT_RESULT_TAMPERED)

                payload_dict = json.loads(result_payload_blob.decode("utf-8"))
                connection.commit()
                return AuthorizationResult(
                    timestamp=current_time,
                    version=__version__,
                    status=AuthStatus.IDEMPOTENT_REPLAY,
                    payload=payload_dict,
                )

            # Atomically lock and validate live authority states
            state_row = connection.execute(
                "SELECT packed_state FROM principals WHERE principal_id = ?",
                (claims.normalized_principal,),
            ).fetchone()
            if state_row is None:
                raise AuthorizationRejected(AuthStatus.REJECT_UNKNOWN_PRINCIPAL)
            live_state = _state_from_blob(state_row[0])

            issuer_row = connection.execute(
                "SELECT issuer_epoch FROM issuers WHERE issuer_digest = ?",
                (claims.issuer_digest,),
            ).fetchone()
            if issuer_row is None:
                raise AuthorizationRejected(AuthStatus.REJECT_UNKNOWN_ISSUER)
            live_issuer_epoch = _uint64_from_blob(issuer_row[0], "issuer_epoch")

            policy_row = connection.execute(
                "SELECT policy_digest FROM policies WHERE policy_name = ?",
                (normalize_context(expected_policy_name, "expected_policy_name"),),
            ).fetchone()
            if policy_row is None:
                raise AuthorizationRejected(AuthStatus.REJECT_UNKNOWN_POLICY)
            live_policy_digest = policy_row[0]

            if (claims.packed_state ^ live_state) != 0:
                raise AuthorizationRejected(AuthStatus.REJECT_STATE_MISMATCH)
            if claims.issuer_epoch != live_issuer_epoch:
                raise AuthorizationRejected(AuthStatus.REJECT_ISSUER_EPOCH_MISMATCH)
            if not hmac.compare_digest(claims.policy_digest, live_policy_digest):
                raise AuthorizationRejected(AuthStatus.REJECT_POLICY_MISMATCH)

            if crash_point == "after_authority_check":
                raise RuntimeError("crash: after_authority_check")

            src_row = connection.execute(
                "SELECT balance_minor FROM accounts WHERE account_id = ?",
                (source_account,),
            ).fetchone()
            if src_row is None:
                raise AuthorizationRejected(AuthStatus.REJECT_UNKNOWN_ACCOUNT)
            if src_row[0] < amount_minor:
                raise AuthorizationRejected(AuthStatus.REJECT_INSUFFICIENT_FUNDS)

            dst_row = connection.execute(
                "SELECT balance_minor FROM accounts WHERE account_id = ?",
                (destination_account,),
            ).fetchone()
            if dst_row is None:
                raise AuthorizationRejected(AuthStatus.REJECT_UNKNOWN_ACCOUNT)

            if dst_row[0] > MAX_TIMESTAMP - amount_minor:
                raise AuthorizationRejected(AuthStatus.REJECT_BALANCE_OVERFLOW)

            connection.execute(
                "UPDATE accounts SET balance_minor = balance_minor - ?, version = version + 1 WHERE account_id = ?",
                (amount_minor, source_account),
            )
            connection.execute(
                "UPDATE accounts SET balance_minor = balance_minor + ?, version = version + 1 WHERE account_id = ?",
                (amount_minor, destination_account),
            )

            if crash_point == "after_ledger_mutation":
                raise RuntimeError("crash: after_ledger_mutation")

            result_payload_dict = {
                "source_account": source_account,
                "destination_account": destination_account,
                "amount_minor": amount_minor,
                "new_source_balance": src_row[0] - amount_minor,
                "new_destination_balance": dst_row[0] + amount_minor,
            }
            result_payload_bytes = canonical_json_object(result_payload_dict)
            result_digest = hashlib.sha256(result_payload_bytes).digest()

            # Sign receipt using dedicated receipt signer
            receipt_payload = (
                claims.credential_id
                + claims.token_digest
                + claims.request_digest
                + result_digest
            )
            receipt_signature = self.receipt_keyring.sign(self.receipt_key_id, receipt_payload, claims.issuer_digest)

            connection.execute(
                "INSERT INTO credential_results("
                "credential_id, token_digest, request_digest, result_payload, result_digest, receipt_signature, receipt_key_id, principal_digest, committed_at, expires_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    claims.credential_id,
                    claims.token_digest,
                    claims.request_digest,
                    result_payload_bytes,
                    result_digest,
                    receipt_signature,
                    self.receipt_key_id,
                    claims.principal_digest,
                    current_time,
                    claims.expires_at,
                ),
            )

            self.database.append_audit_log(
                connection,
                self.audit_key,
                {
                    "action": "transfer",
                    "principal_digest": claims.principal_digest.hex(),
                    "credential_id": claims.credential_id.hex(),
                    "request_digest": claims.request_digest.hex(),
                    "result_digest": result_digest.hex(),
                    "status": AuthStatus.COMMIT_SUCCESS.value,
                    "timestamp": current_time,
                },
            )

            if crash_point == "before_commit":
                raise RuntimeError("crash: before_commit")

            connection.commit()

            return AuthorizationResult(
                timestamp=current_time,
                version=__version__,
                status=AuthStatus.COMMIT_SUCCESS,
                payload=result_payload_dict,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
