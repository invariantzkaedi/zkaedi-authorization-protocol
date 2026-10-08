from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from src.context_bound_epoch_protocol import (
    PROTOCOL_VERSION,
    MAX_TIMESTAMP,
    UINT64_MAX,
    SHA256_SIZE,
    KEY_ID_SIZE,
    CREDENTIAL_ID_SIZE,
    MAX_REQUEST_BYTES,
    MAX_AUDIT_PAYLOAD_BYTES,
    MAX_CREDENTIAL_LIFETIME_SECONDS,
    MAX_CLOCK_SKEW_SECONDS,
    EXPECTED_TOKEN_SIZE,
    EXPECTED_PAYLOAD_SIZE,
    CREDENTIAL_PAYLOAD,
    AuthStatus,
    KeyStatus,
    KeyPurpose,
    AuthorizationRejected,
    MigrationError,
    IssuanceSnapshot,
    CredentialClaims,
    AuthorizationResult,
    KeyRecord,
    validate_timestamp,
    validate_time_window,
    normalize_context,
    pack_state,
    unpack_state,
    advance_epoch,
    parse_strict_json,
    canonical_json,
    canonical_json_object,
    _field_digest,
    _scope_digest,
    _state_to_blob,
    _state_from_blob,
    _uint64_to_blob,
    _uint64_from_blob,
    Ed25519KeyRing,
    CredentialCodec,
    AuthorizationDatabase,
    LinearizableEngine,
)


class TestTGM5Vector1NominalAndCrypto(unittest.TestCase):
    """Vector 1: Nominal End-to-End Keyring, Codec, Ledger, and Audit Log."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "nominal.db")
        self.db = AuthorizationDatabase(self.db_path)
        self.audit_key = secrets.token_bytes(32)
        self.principal_binding_key = secrets.token_bytes(32)

        self.cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        self.receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, self.db)

        self.issuer = "https://issuer.corp.net"
        self.issuer_digest = _field_digest(b"issuer-v1", self.issuer)

        self.cred_key_id = self.cred_keyring.generate(self.issuer)
        self.receipt_key_id = self.receipt_keyring.generate(self.issuer)

        self.codec = CredentialCodec(self.cred_keyring, self.principal_binding_key, "prod-us-east-1")
        self.engine = LinearizableEngine(
            self.db,
            self.codec,
            self.audit_key,
            self.receipt_keyring,
            self.receipt_key_id,
        )

        self.principal_id = "user_alpha"
        self.db.initialize_principal(self.principal_id, pack_state(1, 1, 1, 1, 1))
        self.db.initialize_issuer(self.issuer, 0)
        self.policy_name = "transfer_policy"
        self.policy_dict = {"max_limit": 100000}
        self.policy_digest = self.db.set_policy(self.policy_name, canonical_json_object(self.policy_dict))

        self.db.create_account("acct_src", 10000)
        self.db.create_account("acct_dst", 5000)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_nominal_transfer_and_audit_verification(self):
        current_time = 1700000000
        req_dict = {
            "action": "transfer",
            "amount_minor": 1500,
            "source_account": "acct_src",
            "destination_account": "acct_dst",
        }
        req_bytes = canonical_json_object(req_dict)

        snapshot = self.db.issuance_snapshot(self.principal_id, self.issuer, self.policy_name)
        cred_id = secrets.token_bytes(16)

        token = self.codec.issue(
            key_id=self.cred_key_id,
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience="https://api.vault",
            resource="ledger",
            action="transfer",
            request_bytes=req_bytes,
            policy_digest=snapshot.policy_digest,
            issuer_epoch=snapshot.issuer_epoch,
            packed_state=snapshot.packed_state,
            issued_at=current_time,
            not_before=current_time,
            expires_at=current_time + 300,
            credential_id=cred_id,
        )
        self.assertEqual(len(token), EXPECTED_TOKEN_SIZE)

        res = self.engine.execute_transfer(
            token,
            current_time=current_time,
            expected_issuer=self.issuer,
            expected_principal_id=self.principal_id,
            expected_audience="https://api.vault",
            expected_resource="ledger",
            expected_action="transfer",
            expected_request_bytes=req_bytes,
            expected_policy_name=self.policy_name,
        )
        self.assertEqual(res.status, AuthStatus.COMMIT_SUCCESS)
        self.assertEqual(self.db.balance("acct_src"), 8500)
        self.assertEqual(self.db.balance("acct_dst"), 6500)

        # Audit log check
        valid, count, latest_hash = self.db.verify_audit_log(self.audit_key)
        self.assertTrue(valid)
        self.assertEqual(count, 1)

        # Verify with trusted checkpoint
        valid_cp, _, _ = self.db.verify_audit_log(self.audit_key, (1, latest_hash))
        self.assertTrue(valid_cp)

    def test_key_encrypted_pem_export_import_and_rotation(self):
        password = b"SuperSecretPass123!"
        encrypted_pem = self.cred_keyring.export_private_encrypted(self.cred_key_id, password)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", encrypted_pem)

        # Import into fresh keyring
        fresh_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        fresh_keyring.register_private_encrypted(
            self.cred_key_id, encrypted_pem, password, self.issuer, requested_status=KeyStatus.ACTIVE
        )
        self.assertEqual(fresh_keyring._records[self.cred_key_id].status, KeyStatus.ACTIVE)
        self.assertEqual(self.db.get_persisted_key_status(self.cred_key_id), KeyStatus.ACTIVE)

        # Key rotation to VERIFY_ONLY and then RETIRED
        self.cred_keyring.transition(self.cred_key_id, KeyStatus.VERIFY_ONLY)
        self.assertEqual(self.cred_keyring._records[self.cred_key_id].status, KeyStatus.VERIFY_ONLY)
        self.assertEqual(self.db.get_persisted_key_status(self.cred_key_id), KeyStatus.VERIFY_ONLY)

        # Purge receipts and verify retirement
        self.db.purge_expired_receipts(1800000000)
        self.assertTrue(self.db.can_retire_key(self.receipt_key_id, 1800000000))

        self.cred_keyring.transition(self.cred_key_id, KeyStatus.RETIRED)
        self.assertEqual(self.cred_keyring._records[self.cred_key_id].status, KeyStatus.RETIRED)
        self.assertEqual(self.db.get_persisted_key_status(self.cred_key_id), KeyStatus.RETIRED)


class TestTGM5Vector2BoundaryAndRejections(unittest.TestCase):
    """Vector 2: Boundary Validations, Codec Limits, and Strict Parsing."""

    def test_validate_timestamp_boundaries(self):
        validate_timestamp(0, "ts")
        validate_timestamp(MAX_TIMESTAMP, "ts")
        with self.assertRaises(TypeError):
            validate_timestamp(True, "ts")
        with self.assertRaises(TypeError):
            validate_timestamp(123.45, "ts")
        with self.assertRaises(ValueError):
            validate_timestamp(-1, "ts")
        with self.assertRaises(ValueError):
            validate_timestamp(MAX_TIMESTAMP + 1, "ts")

    def test_validate_time_window_boundaries(self):
        validate_time_window(100, 100, 200)
        with self.assertRaises(ValueError):
            validate_time_window(150, 100, 200)  # issued_at > not_before
        with self.assertRaises(ValueError):
            validate_time_window(100, 200, 200)  # not_before >= expires_at
        with self.assertRaises(ValueError):
            validate_time_window(100, 100, 100 + MAX_CREDENTIAL_LIFETIME_SECONDS + 1)  # lifetime > max_lifetime

    def test_normalize_context_boundaries(self):
        self.assertEqual(normalize_context("valid_ctx", "f"), "valid_ctx")
        with self.assertRaises(TypeError):
            normalize_context(12345, "f")
        with self.assertRaises(ValueError):
            normalize_context("", "f")
        with self.assertRaises(ValueError):
            normalize_context("a" * 1025, "f")
        with self.assertRaises(ValueError):
            normalize_context("bad\x00char", "f")
        with self.assertRaises(ValueError):
            normalize_context("bad\x1fchar", "f")
        with self.assertRaises(ValueError):
            normalize_context("bad\x7fchar", "f")

    def test_pack_and_unpack_state_boundaries(self):
        packed = pack_state(65535, 4095, 4095, 4095, 4095)
        self.assertEqual(unpack_state(packed), (65535, 4095, 4095, 4095, 4095))

        with self.assertRaises(TypeError):
            pack_state(True, 1, 1, 1, 1)
        with self.assertRaises(ValueError):
            pack_state(-1, 1, 1, 1, 1)
        with self.assertRaises(ValueError):
            pack_state(65536, 1, 1, 1, 1)
        with self.assertRaises(ValueError):
            pack_state(1, 4096, 1, 1, 1)
        with self.assertRaises(ValueError):
            pack_state(1, 1, 4096, 1, 1)
        with self.assertRaises(ValueError):
            pack_state(1, 1, 1, 4096, 1)
        with self.assertRaises(ValueError):
            pack_state(1, 1, 1, 1, 4096)

        with self.assertRaises(TypeError):
            unpack_state(False)
        with self.assertRaises(ValueError):
            unpack_state(-1)
        with self.assertRaises(ValueError):
            unpack_state(UINT64_MAX + 1)

    def test_advance_epoch_all_fields(self):
        s = pack_state(1, 1, 1, 1, 1)
        s_sess = advance_epoch(s, "session")
        self.assertEqual(unpack_state(s_sess), (1, 1, 1, 1, 2))

        # Roll over session
        s_max_sess = pack_state(1, 1, 1, 1, 4095)
        s_rolled = advance_epoch(s_max_sess, "session")
        self.assertEqual(unpack_state(s_rolled), (2, 1, 1, 1, 1))

        with self.assertRaises(ValueError):
            advance_epoch(s, "invalid_field")

        s_max_gen = pack_state(65535, 1, 1, 1, 4095)
        with self.assertRaises(OverflowError):
            advance_epoch(s_max_gen, "session")

    def test_parse_strict_json_and_canonical_json(self):
        valid_json = b'{"action": "transfer", "amount": 100, "flag": true, "nullval": null}'
        parsed = parse_strict_json(valid_json)
        self.assertEqual(parsed["action"], "transfer")

        with self.assertRaises(TypeError):
            parse_strict_json("not bytes")
        with self.assertRaises(ValueError):
            parse_strict_json(b"")
        with self.assertRaises(ValueError):
            parse_strict_json(b"a" * (MAX_REQUEST_BYTES + 1))
        with self.assertRaises(ValueError):
            parse_strict_json(b'{"a": 1, "a": 2}')  # duplicate key
        with self.assertRaises(ValueError):
            parse_strict_json(b'{"amount": 12.34}')  # float rejection
        with self.assertRaises(ValueError):
            parse_strict_json(b'{"amount": 9999999999999999999999}')  # overflow int
        with self.assertRaises(ValueError):
            parse_strict_json(b"\xff\xfe\xfd")  # invalid utf-8

        # canonical_json_object validation
        with self.assertRaises(ValueError):
            canonical_json_object({"invalid": float("nan")})

    def test_blob_helper_functions(self):
        s_blob = _state_to_blob(123456)
        self.assertEqual(_state_from_blob(s_blob), 123456)
        with self.assertRaises(ValueError):
            _state_from_blob(b"short")

        u_blob = _uint64_to_blob(999, "u_test")
        self.assertEqual(_uint64_from_blob(u_blob, "u_test"), 999)
        with self.assertRaises(ValueError):
            _uint64_from_blob(b"short", "u_test")

        with self.assertRaises(ValueError):
            _uint64_to_blob(-1, "u_neg")
        with self.assertRaises(ValueError):
            _uint64_to_blob(UINT64_MAX + 1, "u_over")
        with self.assertRaises(ValueError):
            _uint64_to_blob(True, "u_bool")


class TestTGM5Vector3FaultsAndSecurityRejections(unittest.TestCase):
    """Vector 3: Codec Rejection Status Codes, Security Violations, and Faults."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db = AuthorizationDatabase(os.path.join(self.tmp_dir.name, "faults.db"))
        self.audit_key = secrets.token_bytes(32)
        self.binding_key = secrets.token_bytes(32)

        self.cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        self.receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, self.db)

        self.issuer = "https://issuer.corp.net"
        self.issuer_digest = _field_digest(b"issuer-v1", self.issuer)

        self.cred_k_id = self.cred_keyring.generate(self.issuer)
        self.receipt_k_id = self.receipt_keyring.generate(self.issuer)

        self.codec = CredentialCodec(self.cred_keyring, self.binding_key, "prod-us-east-1")
        self.engine = LinearizableEngine(
            self.db, self.codec, self.audit_key, self.receipt_keyring, self.receipt_k_id
        )

        self.principal_id = "user_faults"
        self.packed_state = pack_state(1, 1, 1, 1, 1)
        self.db.initialize_principal(self.principal_id, self.packed_state)
        self.db.initialize_issuer(self.issuer, 0)
        self.policy_name = "policy_faults"
        self.policy_digest = self.db.set_policy(self.policy_name, b'{"rule": 1}')

        self.db.create_account("acc1", 1000)
        self.db.create_account("acc2", 1000)

        self.current_time = 1700000000
        self.req_dict = {
            "action": "transfer",
            "amount_minor": 100,
            "source_account": "acc1",
            "destination_account": "acc2",
        }
        self.req_bytes = canonical_json_object(self.req_dict)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_codec_verify_all_rejection_codes(self):
        valid_token = self.codec.issue(
            key_id=self.cred_k_id,
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience="https://api.vault",
            resource="ledger",
            action="transfer",
            request_bytes=self.req_bytes,
            policy_digest=self.policy_digest,
            issuer_epoch=0,
            packed_state=self.packed_state,
            issued_at=self.current_time,
            not_before=self.current_time,
            expires_at=self.current_time + 300,
            credential_id=secrets.token_bytes(16),
        )

        # 1. Malformed payload length
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token[:-1], current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_MALFORMED_PAYLOAD)

        # 2. Version mismatch with signed payload
        bad_ver_payload = CREDENTIAL_PAYLOAD.pack(
            0x99,
            self.cred_k_id,
            0,
            self.packed_state,
            self.current_time,
            self.current_time,
            self.current_time + 300,
            secrets.token_bytes(16),
            self.issuer_digest,
            self.codec._principal_digest(self.principal_id),
            _field_digest(b"audience-v1", "https://api.vault"),
            _scope_digest("ledger", "transfer", "prod-us-east-1"),
            hashlib.sha256(canonical_json(self.req_bytes)).digest(),
            self.policy_digest,
        )
        bad_ver_sig = self.cred_keyring.sign(self.cred_k_id, bad_ver_payload, self.issuer_digest)
        bad_ver_token = bad_ver_payload + bad_ver_sig
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(bad_ver_token, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_VERSION_MISMATCH)

        # 3. Clock skew future
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=self.current_time - 100, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_ISSUED_IN_FUTURE)

        # 4. Expired
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=self.current_time + 400, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_EXPIRED)

        # 5. Mismatched Issuer
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=self.current_time, expected_issuer="https://wrong-issuer.net", expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_ISSUER_MISMATCH)

        # 6. Mismatched Principal
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id="wrong_user", expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_PRINCIPAL_MISMATCH)

        # 7. Mismatched Audience
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://wrong.aud", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_AUDIENCE_MISMATCH)

        # 8. Mismatched Scope (resource/action)
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="wrong_res", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_SCOPE_MISMATCH)

        # 9. Mismatched Request Bytes
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=b'{"action": "tampered"}')
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_REQUEST_DIGEST_MISMATCH)

        # 10. Invalid Signature
        tampered_sig = bytearray(valid_token)
        tampered_sig[-1] ^= 0xFF
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(bytes(tampered_sig), current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_INVALID_SIGNATURE)

        # 11. Invalid Current Time
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(valid_token, current_time=-1, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_INVALID_CURRENT_TIME)

        # 12. Invalid time window in token payload
        bad_tw_payload = CREDENTIAL_PAYLOAD.pack(
            PROTOCOL_VERSION,
            self.cred_k_id,
            0,
            self.packed_state,
            self.current_time + 100,  # issued_at > not_before
            self.current_time,        # not_before
            self.current_time + 300,  # expires_at
            secrets.token_bytes(16),
            self.issuer_digest,
            self.codec._principal_digest(self.principal_id),
            _field_digest(b"audience-v1", "https://api.vault"),
            _scope_digest("ledger", "transfer", "prod-us-east-1"),
            hashlib.sha256(canonical_json(self.req_bytes)).digest(),
            self.policy_digest,
        )
        bad_tw_sig = self.cred_keyring.sign(self.cred_k_id, bad_tw_payload, self.issuer_digest)
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(bad_tw_payload + bad_tw_sig, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_INVALID_TIME_WINDOW)

        # 13. Lifetime exceeded in token payload
        bad_lt_payload = CREDENTIAL_PAYLOAD.pack(
            PROTOCOL_VERSION,
            self.cred_k_id,
            0,
            self.packed_state,
            self.current_time,
            self.current_time,
            self.current_time + MAX_CREDENTIAL_LIFETIME_SECONDS + 10,
            secrets.token_bytes(16),
            self.issuer_digest,
            self.codec._principal_digest(self.principal_id),
            _field_digest(b"audience-v1", "https://api.vault"),
            _scope_digest("ledger", "transfer", "prod-us-east-1"),
            hashlib.sha256(canonical_json(self.req_bytes)).digest(),
            self.policy_digest,
        )
        bad_lt_sig = self.cred_keyring.sign(self.cred_k_id, bad_lt_payload, self.issuer_digest)
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(bad_lt_payload + bad_lt_sig, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_LIFETIME_EXCEEDED)

        # 14. Not yet valid in token payload
        bad_nyv_payload = CREDENTIAL_PAYLOAD.pack(
            PROTOCOL_VERSION,
            self.cred_k_id,
            0,
            self.packed_state,
            self.current_time,
            self.current_time + 100,
            self.current_time + 400,
            secrets.token_bytes(16),
            self.issuer_digest,
            self.codec._principal_digest(self.principal_id),
            _field_digest(b"audience-v1", "https://api.vault"),
            _scope_digest("ledger", "transfer", "prod-us-east-1"),
            hashlib.sha256(canonical_json(self.req_bytes)).digest(),
            self.policy_digest,
        )
        bad_nyv_sig = self.cred_keyring.sign(self.cred_k_id, bad_nyv_payload, self.issuer_digest)
        with self.assertRaises(AuthorizationRejected) as cm:
            self.codec.verify(bad_nyv_payload + bad_nyv_sig, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id=self.principal_id, expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=self.req_bytes)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_NOT_YET_VALID)

    def test_keyring_and_engine_initialization_faults(self):
        with self.assertRaises(TypeError):
            Ed25519KeyRing("invalid_purpose", self.db)

        with self.assertRaises(ValueError):
            CredentialCodec(self.cred_keyring, b"short_key", "prod")

        with self.assertRaises(ValueError):
            CredentialCodec(self.receipt_keyring, self.binding_key, "prod")  # wrong purpose

        with self.assertRaises(ValueError):
            LinearizableEngine(self.db, self.codec, b"short_audit_key", self.receipt_keyring, self.receipt_k_id)

        with self.assertRaises(RuntimeError):
            LinearizableEngine(self.db, self.codec, self.audit_key, None, None)

        with self.assertRaises(ValueError):
            # Key separation violation (same keyring)
            LinearizableEngine(self.db, self.codec, self.audit_key, self.cred_keyring, self.cred_k_id)

        # Key separation violation (same public key on different keyrings)
        foreign_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, database=None)
        cred_pub = self.cred_keyring.export_public(self.cred_k_id)
        fk_id = secrets.token_bytes(16)
        foreign_keyring.register_public(fk_id, cred_pub, self.issuer, KeyStatus.ACTIVE)
        with self.assertRaises(ValueError):
            LinearizableEngine(self.db, self.codec, self.audit_key, foreign_keyring, fk_id)

        # Receipt keyring with wrong purpose
        distinct_cred_ring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=None)
        d_kid = distinct_cred_ring.generate(self.issuer)
        with self.assertRaises(ValueError):
            LinearizableEngine(self.db, self.codec, self.audit_key, distinct_cred_ring, d_kid)

        # Codec issue validations
        with self.assertRaises(ValueError):
            self.codec.issue(
                key_id=b"short", packed_state=self.packed_state, issuer_epoch=0,
                issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
                issuer=self.issuer, principal_id=self.principal_id, audience="https://api",
                resource="ledger", action="transfer", request_bytes=self.req_bytes, policy_digest=self.policy_digest
            )
        with self.assertRaises(ValueError):
            self.codec.issue(
                key_id=self.cred_k_id, packed_state=self.packed_state, issuer_epoch=0,
                issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
                issuer=self.issuer, principal_id=self.principal_id, audience="https://api",
                resource="ledger", action="transfer", request_bytes=self.req_bytes, policy_digest=b"short"
            )
        with self.assertRaises(ValueError):
            self.codec.issue(
                key_id=self.cred_k_id, packed_state=self.packed_state, issuer_epoch=0,
                issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
                issuer=self.issuer, principal_id=self.principal_id, audience="https://api",
                resource="ledger", action="transfer", request_bytes=self.req_bytes, policy_digest=self.policy_digest,
                credential_id=b"short"
            )


class TestTGM5Vector4DegradedLedgerAndDatabase(unittest.TestCase):
    """Vector 4: Degraded Ledger Scenarios, Replay Tampering, Triggers, and Migrations."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db = AuthorizationDatabase(os.path.join(self.tmp_dir.name, "degraded.db"))
        self.audit_key = secrets.token_bytes(32)
        self.binding_key = secrets.token_bytes(32)

        self.cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        self.receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, self.db)

        self.issuer = "https://issuer.corp.net"
        self.issuer_digest = _field_digest(b"issuer-v1", self.issuer)

        self.cred_k_id = self.cred_keyring.generate(self.issuer)
        self.receipt_k_id = self.receipt_keyring.generate(self.issuer)

        self.codec = CredentialCodec(self.cred_keyring, self.binding_key, "prod-us-east-1")
        self.engine = LinearizableEngine(
            self.db, self.codec, self.audit_key, self.receipt_keyring, self.receipt_k_id
        )

        self.principal_id = "user_degraded"
        self.packed_state = pack_state(1, 1, 1, 1, 1)
        self.db.initialize_principal(self.principal_id, self.packed_state)
        self.db.initialize_issuer(self.issuer, 0)
        self.policy_name = "policy_degraded"
        self.policy_digest = self.db.set_policy(self.policy_name, b'{"allow": true}')

        self.db.create_account("acct_a", 500)
        self.db.create_account("acct_b", 500)
        self.current_time = 1700000000

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_transfer_rejections_and_crash_points(self):
        # 1. Invalid request json (source == dest)
        bad_req = canonical_json_object({
            "action": "transfer",
            "amount_minor": 100,
            "source_account": "acct_a",
            "destination_account": "acct_a",
        })
        tok = self.codec.issue(
            key_id=self.cred_k_id,
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience="https://api.vault",
            resource="ledger",
            action="transfer",
            request_bytes=bad_req,
            policy_digest=self.policy_digest,
            issuer_epoch=0,
            packed_state=self.packed_state,
            issued_at=self.current_time,
            not_before=self.current_time,
            expires_at=self.current_time + 300,
            credential_id=secrets.token_bytes(16),
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=bad_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_INVALID_REQUEST)

        # 2. Invalid schema (not dict, missing keys, wrong action, non-positive amount)
        for bad_dict in [
            {"action": "not_transfer", "amount_minor": 10, "source_account": "acct_a", "destination_account": "acct_b"},
            {"action": "transfer", "amount_minor": -10, "source_account": "acct_a", "destination_account": "acct_b"},
            {"action": "transfer", "amount_minor": True, "source_account": "acct_a", "destination_account": "acct_b"},
            {"extra_key": 1, "action": "transfer", "amount_minor": 10, "source_account": "acct_a", "destination_account": "acct_b"},
        ]:
            b_bytes = canonical_json_object(bad_dict)
            tok_b = self.codec.issue(
                key_id=self.cred_k_id, issuer=self.issuer, principal_id=self.principal_id,
                audience="https://api.vault", resource="ledger", action="transfer", request_bytes=b_bytes,
                policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
                issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
            )
            with self.assertRaises(AuthorizationRejected) as cm:
                self.engine.execute_transfer(
                    tok_b, current_time=self.current_time, expected_issuer=self.issuer,
                    expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                    expected_resource="ledger", expected_action="transfer", expected_request_bytes=b_bytes,
                    expected_policy_name=self.policy_name,
                )
            self.assertEqual(cm.exception.status, AuthStatus.REJECT_INVALID_REQUEST)

        # 3. Insufficient funds
        over_req = canonical_json_object({
            "action": "transfer",
            "amount_minor": 99999,
            "source_account": "acct_a",
            "destination_account": "acct_b",
        })
        tok_over = self.codec.issue(
            key_id=self.cred_k_id,
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience="https://api.vault",
            resource="ledger",
            action="transfer",
            request_bytes=over_req,
            policy_digest=self.policy_digest,
            issuer_epoch=0,
            packed_state=self.packed_state,
            issued_at=self.current_time,
            not_before=self.current_time,
            expires_at=self.current_time + 300,
            credential_id=secrets.token_bytes(16),
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_over, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=over_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_INSUFFICIENT_FUNDS)

        # 4. Unknown account in live DB
        un_src_req = canonical_json_object({
            "action": "transfer", "amount_minor": 10, "source_account": "unknown_src", "destination_account": "acct_b"
        })
        tok_un_src = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id=self.principal_id,
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=un_src_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_un_src, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=un_src_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_UNKNOWN_ACCOUNT)

        un_dst_req = canonical_json_object({
            "action": "transfer", "amount_minor": 10, "source_account": "acct_a", "destination_account": "unknown_dst"
        })
        tok_un_dst = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id=self.principal_id,
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=un_dst_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_un_dst, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=un_dst_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_UNKNOWN_ACCOUNT)

        # Balance overflow (dst balance > MAX_TIMESTAMP - amount)
        self.db.create_account("acct_overflow_dst", MAX_TIMESTAMP - 5)
        overflow_req = canonical_json_object({
            "action": "transfer", "amount_minor": 10, "source_account": "acct_a", "destination_account": "acct_overflow_dst"
        })
        tok_of = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id=self.principal_id,
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=overflow_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_of, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=overflow_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_BALANCE_OVERFLOW)

        # 5. Live DB authority mismatches (state, issuer epoch, policy, unknown principal/issuer/policy)
        val_req = canonical_json_object({
            "action": "transfer", "amount_minor": 10, "source_account": "acct_a", "destination_account": "acct_b"
        })
        tok_val = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id=self.principal_id,
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=val_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        # Bump state in DB -> state mismatch
        self.db.bump_principal_epoch(self.principal_id, "session")
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_val, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_STATE_MISMATCH)

        # Restore principal state
        conn = self.db.connect()
        conn.execute("UPDATE principals SET packed_state = ? WHERE principal_id = ?", (_state_to_blob(self.packed_state), self.principal_id))
        conn.commit()
        conn.close()

        # JSON parsed is list
        list_req = b'["not", "a", "dict"]'
        tok_list = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id=self.principal_id,
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=list_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_list, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=list_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_INVALID_REQUEST)

        # Issuer epoch mismatch
        self.db.bump_issuer_epoch(self.issuer)
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_val, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_ISSUER_EPOCH_MISMATCH)

        # Reset issuer epoch in DB and test policy mismatch
        conn = self.db.connect()
        conn.execute("UPDATE issuers SET issuer_epoch = ? WHERE issuer_digest = ?", (_uint64_to_blob(0, "e"), self.issuer_digest))
        conn.commit()
        conn.close()

        self.db.set_policy(self.policy_name, b'{"allow": false}')
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_val, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id=self.principal_id, expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_POLICY_MISMATCH)
        self.db.set_policy(self.policy_name, b'{"allow": true}')

        # Unknown principal / issuer / policy in live DB
        tok_unknown_p = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id="unregistered_user",
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=val_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_unknown_p, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id="unregistered_user", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_UNKNOWN_PRINCIPAL)

        self.db.initialize_principal("usr_un_issuer", self.packed_state)
        un_issuer = "https://unregistered_issuer.net"
        un_i_ring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        un_i_kid = un_i_ring.generate(un_issuer)
        un_i_codec = CredentialCodec(un_i_ring, self.binding_key, "prod-us-east-1")
        tok_un_i = un_i_codec.issue(
            key_id=un_i_kid, issuer=un_issuer, principal_id="usr_un_issuer",
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=val_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        engine_with_un_i = LinearizableEngine(self.db, un_i_codec, self.audit_key, self.receipt_keyring, self.receipt_k_id)
        with self.assertRaises(AuthorizationRejected) as cm:
            engine_with_un_i.execute_transfer(
                tok_un_i, current_time=self.current_time, expected_issuer=un_issuer,
                expected_principal_id="usr_un_issuer", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_UNKNOWN_ISSUER)

        tok_un_pol = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id="usr_un_issuer",
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=val_req,
            policy_digest=secrets.token_bytes(32), issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
        )
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_un_pol, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id="usr_un_issuer", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name="nonexistent_policy",
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_UNKNOWN_POLICY)

        # Replay failure branches (conflict, legacy unverified, tampered)
        self.db.initialize_principal("usr_rep", self.packed_state)
        self.db.set_policy(self.policy_name, b'{"allow": true}')
        cred_id_rep = secrets.token_bytes(16)
        tok_rep = self.codec.issue(
            key_id=self.cred_k_id, issuer=self.issuer, principal_id="usr_rep",
            audience="https://api.vault", resource="ledger", action="transfer", request_bytes=val_req,
            policy_digest=self.policy_digest, issuer_epoch=0, packed_state=self.packed_state,
            issued_at=self.current_time, not_before=self.current_time, expires_at=self.current_time + 300,
            credential_id=cred_id_rep,
        )
        res_first = self.engine.execute_transfer(
            tok_rep, current_time=self.current_time, expected_issuer=self.issuer,
            expected_principal_id="usr_rep", expected_audience="https://api.vault",
            expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
            expected_policy_name=self.policy_name,
        )
        self.assertEqual(res_first.status, AuthStatus.COMMIT_SUCCESS)

        # Conflict in token_digest
        conn = self.db.connect()
        conn.execute("UPDATE credential_results SET token_digest = ? WHERE credential_id = ?", (secrets.token_bytes(32), cred_id_rep))
        conn.commit()
        conn.close()
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_rep, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id="usr_rep", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_CREDENTIAL_CONFLICT)

        # Conflict in principal_digest
        claims = self.codec.verify(tok_rep, current_time=self.current_time, expected_issuer=self.issuer, expected_principal_id="usr_rep", expected_audience="https://api.vault", expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req)
        conn = self.db.connect()
        conn.execute("UPDATE credential_results SET token_digest = ?, principal_digest = ? WHERE credential_id = ?", (claims.token_digest, secrets.token_bytes(32), cred_id_rep))
        conn.commit()
        conn.close()
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_rep, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id="usr_rep", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_CREDENTIAL_CONFLICT)

        # Conflict in request_digest
        conn = self.db.connect()
        conn.execute("UPDATE credential_results SET principal_digest = ?, request_digest = ? WHERE credential_id = ?", (claims.principal_digest, secrets.token_bytes(32), cred_id_rep))
        conn.commit()
        conn.close()
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_rep, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id="usr_rep", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_CREDENTIAL_CONFLICT)

        # Legacy unverified result (receipt signature is NULL)
        conn = self.db.connect()
        conn.execute("UPDATE credential_results SET request_digest = ?, receipt_signature = NULL WHERE credential_id = ?", (claims.request_digest, cred_id_rep))
        conn.commit()
        conn.close()
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_rep, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id="usr_rep", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_LEGACY_RESULT_UNVERIFIED)

        # Tampered result payload (result_digest mismatch)
        conn = self.db.connect()
        conn.execute("UPDATE credential_results SET receipt_signature = ?, result_payload = ? WHERE credential_id = ?", (secrets.token_bytes(64), b'{"tampered":1}', cred_id_rep))
        conn.commit()
        conn.close()
        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok_rep, current_time=self.current_time, expected_issuer=self.issuer,
                expected_principal_id="usr_rep", expected_audience="https://api.vault",
                expected_resource="ledger", expected_action="transfer", expected_request_bytes=val_req,
                expected_policy_name=self.policy_name,
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_RESULT_TAMPERED)

        # 6. Crash points
        valid_req = canonical_json_object({
            "action": "transfer",
            "amount_minor": 50,
            "source_account": "acct_a",
            "destination_account": "acct_b",
        })
        # Reset principal state
        self.db.initialize_principal("usr_cp_test", self.packed_state)
        tok_crash = self.codec.issue(
            key_id=self.cred_k_id,
            issuer=self.issuer,
            principal_id="usr_cp_test",
            audience="https://api.vault",
            resource="ledger",
            action="transfer",
            request_bytes=valid_req,
            policy_digest=self.policy_digest,
            issuer_epoch=0,
            packed_state=self.packed_state,
            issued_at=self.current_time,
            not_before=self.current_time,
            expires_at=self.current_time + 300,
            credential_id=secrets.token_bytes(16),
        )
        for cp in ["after_begin", "after_authority_check", "after_ledger_mutation", "before_commit"]:
            with self.assertRaises(RuntimeError):
                self.engine.execute_transfer(
                    tok_crash, current_time=self.current_time, expected_issuer=self.issuer,
                    expected_principal_id="usr_cp_test", expected_audience="https://api.vault",
                    expected_resource="ledger", expected_action="transfer", expected_request_bytes=valid_req,
                    expected_policy_name=self.policy_name, crash_point=cp,
                )

    def test_database_triggers_and_table_constraints(self):
        conn = self.db.connect()
        # Direct DELETE on key_records must be blocked by trigger
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM key_records WHERE key_id = ?", (self.cred_k_id,))

        # Cannot reactivate retired key
        conn.execute("UPDATE key_records SET status = 'retired' WHERE key_id = ?", (self.cred_k_id,))
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE key_records SET status = 'active' WHERE key_id = ?", (self.cred_k_id,))
        conn.close()

    def test_audit_log_tampering_and_checkpoints(self):
        # Empty log with invalid checkpoint
        valid, _, _ = self.db.verify_audit_log(self.audit_key, (1, secrets.token_bytes(32)))
        self.assertFalse(valid)

        # Append two log entries
        conn = self.db.connect()
        h1 = self.db.append_audit_log(conn, self.audit_key, {"event": "1"})
        h2 = self.db.append_audit_log(conn, self.audit_key, {"event": "2"})
        conn.close()

        # Tamper second event hash
        conn = self.db.connect()
        conn.execute("DROP TRIGGER IF EXISTS audit_events_update_guard")
        conn.execute("UPDATE audit_events SET event_hash = ? WHERE sequence = 2", (secrets.token_bytes(32),))
        conn.commit()
        conn.close()

        valid, count, _ = self.db.verify_audit_log(self.audit_key)
        self.assertFalse(valid)

        # Tamper second previous_hash (line 1439)
        conn = self.db.connect()
        conn.execute("UPDATE audit_events SET event_hash = ?, previous_hash = ? WHERE sequence = 2", (h2, secrets.token_bytes(32)))
        conn.commit()
        conn.close()
        valid, _, _ = self.db.verify_audit_log(self.audit_key)
        self.assertFalse(valid)

        # Mismatched checkpoint hash when sequence matches (line 1452)
        conn = self.db.connect()
        conn.execute("UPDATE audit_events SET previous_hash = ? WHERE sequence = 2", (h1,))
        conn.commit()
        conn.close()
        valid, _, _ = self.db.verify_audit_log(self.audit_key, (2, secrets.token_bytes(32)))
        self.assertFalse(valid)


class TestKeyRingAndCodecComprehensiveBranches(unittest.TestCase):
    """Detailed Branch Coverage for KeyRing, Codec, Database methods."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = AuthorizationDatabase(os.path.join(self.tmp_dir.name, "detailed.db"))
        self.issuer = "https://auth.net"
        self.issuer_digest = _field_digest(b"issuer-v1", self.issuer)
        self.cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        self.receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, self.db)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_keyring_registration_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            self.cred_keyring.register_public(b"short", b"0" * 32, self.issuer)
        with self.assertRaises(TypeError):
            self.cred_keyring.register_public(secrets.token_bytes(16), b"short", self.issuer)
        with self.assertRaises(TypeError):
            self.cred_keyring.register_private(b"short", b"0" * 32, self.issuer)
        with self.assertRaises(TypeError):
            self.cred_keyring.register_private(secrets.token_bytes(16), b"short", self.issuer)

        # Encrypted PEM registration branches
        k_id = secrets.token_bytes(16)
        with self.assertRaises(TypeError):
            self.cred_keyring.register_private_encrypted(k_id, "not bytes", b"pass", self.issuer)
        with self.assertRaises(TypeError):
            self.cred_keyring.register_private_encrypted(k_id, b"", b"pass", self.issuer)
        with self.assertRaises(TypeError):
            self.cred_keyring.register_private_encrypted(k_id, b"data", "not bytes", self.issuer)
        with self.assertRaises(TypeError):
            self.cred_keyring.register_private_encrypted(k_id, b"data", b"", self.issuer)

        # Non-Ed25519 key in PEM (e.g. RSA key)
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"pass"),
        )
        with self.assertRaises(ValueError):
            self.cred_keyring.register_private_encrypted(k_id, rsa_pem, b"pass", self.issuer)

    def test_keyring_export_and_sign_errors(self):
        with self.assertRaises(KeyError):
            self.cred_keyring.export_public(secrets.token_bytes(16))
        with self.assertRaises(ValueError):
            self.cred_keyring.export_private_encrypted(secrets.token_bytes(16), "not bytes")
        with self.assertRaises(ValueError):
            self.cred_keyring.export_private_encrypted(secrets.token_bytes(16), b"")
        with self.assertRaises(KeyError):
            self.cred_keyring.export_private_encrypted(secrets.token_bytes(16), b"pass")

        k_id = self.cred_keyring.generate(self.issuer)
        self.cred_keyring.transition(k_id, KeyStatus.VERIFY_ONLY)
        with self.assertRaises(KeyError):
            self.cred_keyring.export_private_encrypted(k_id, b"pass")

        # Test ValueError when record has private_key but status is not ACTIVE
        priv = ed25519.Ed25519PrivateKey.generate()
        k_non_active = secrets.token_bytes(16)
        self.cred_keyring._records[k_non_active] = KeyRecord(
            priv.public_key(),
            priv,
            KeyStatus.VERIFY_ONLY,
            KeyPurpose.CREDENTIAL_SIGNING,
            self.issuer_digest,
        )
        with self.assertRaises(ValueError):
            self.cred_keyring.export_private_encrypted(k_non_active, b"pass")

        # Key transition errors
        with self.assertRaises(TypeError):
            self.cred_keyring.transition(k_id, "invalid")
        with self.assertRaises(KeyError):
            self.cred_keyring.transition(secrets.token_bytes(16), KeyStatus.RETIRED)
        with self.assertRaises(ValueError):
            self.cred_keyring.transition(k_id, KeyStatus.ACTIVE)

        # Sign errors
        with self.assertRaises(ValueError):
            self.cred_keyring.sign(secrets.token_bytes(16), b"payload", self.issuer_digest)
        with self.assertRaises(ValueError):
            self.cred_keyring.sign(k_id, b"payload", self.issuer_digest)  # not active

        # Sign on standalone keyring without DB where record status is VERIFY_ONLY or private key is None
        standalone_ring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=None)
        k_vo = standalone_ring.generate(self.issuer)
        standalone_ring.transition(k_vo, KeyStatus.VERIFY_ONLY)
        with self.assertRaises(ValueError):
            standalone_ring.sign(k_vo, b"payload", self.issuer_digest)

        k_pub_only = secrets.token_bytes(16)
        standalone_ring.register_public(k_pub_only, b"p" * 32, self.issuer, status=KeyStatus.ACTIVE)
        with self.assertRaises(ValueError):
            standalone_ring.sign(k_pub_only, b"payload", self.issuer_digest)

        # _register validation
        with self.assertRaises(TypeError):
            self.cred_keyring._register(b"short", ed25519.Ed25519PrivateKey.generate().public_key(), None, KeyStatus.ACTIVE, self.issuer_digest)
        with self.assertRaises(TypeError):
            self.cred_keyring._register(secrets.token_bytes(16), ed25519.Ed25519PrivateKey.generate().public_key(), None, "not_status", self.issuer_digest)
        with self.assertRaises(ValueError):
            self.cred_keyring._register(secrets.token_bytes(16), ed25519.Ed25519PrivateKey.generate().public_key(), None, KeyStatus.ACTIVE, b"short")
        with self.assertRaises(ValueError):
            # Key ID collision
            existing_k_id = list(self.cred_keyring._records.keys())[0]
            self.cred_keyring._register(existing_k_id, ed25519.Ed25519PrivateKey.generate().public_key(), None, KeyStatus.ACTIVE, self.issuer_digest)

        # Reactivate rotated/retired key in register_private_encrypted
        k_rotated = self.cred_keyring.generate(self.issuer)
        pem_rot = self.cred_keyring.export_private_encrypted(k_rotated, b"pass")
        self.cred_keyring.transition(k_rotated, KeyStatus.VERIFY_ONLY)
        with self.assertRaises(ValueError):
            self.cred_keyring.register_private_encrypted(k_rotated, pem_rot, b"pass", self.issuer, requested_status=KeyStatus.ACTIVE)

        # Inactive receipt keyring in LinearizableEngine
        inactive_receipt_ring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, self.db)
        inact_k_id = inactive_receipt_ring.generate(self.issuer)
        inactive_receipt_ring.transition(inact_k_id, KeyStatus.VERIFY_ONLY)
        codec = CredentialCodec(self.cred_keyring, b"b" * 32, "prod")
        with self.assertRaises(ValueError):
            LinearizableEngine(self.db, codec, b"a" * 32, inactive_receipt_ring, inact_k_id)

    def test_database_crud_and_lookup_branches(self):
        self.db.initialize_principal("usr_t", pack_state(1, 1, 1, 1, 1))
        with self.assertRaises(ValueError):
            self.db.initialize_principal("usr_t", pack_state(2, 2, 2, 2, 2))

        self.db.initialize_issuer("https://auth.net", 0)
        with self.assertRaises(ValueError):
            self.db.initialize_issuer("https://auth.net", 1)

        with self.assertRaises(ValueError):
            self.db.set_policy("bad_pol", b"")

        with self.assertRaises(TypeError):
            self.db.create_account("acct_bad", True)
        with self.assertRaises(TypeError):
            self.db.create_account("acct_bad", 12.34)
        with self.assertRaises(ValueError):
            self.db.create_account("acct_bad", -1)
        with self.assertRaises(ValueError):
            self.db.create_account("acct_bad", 9223372036854775808)

        self.db.create_account("acct_ok", 100)
        with self.assertRaises(ValueError):
            self.db.create_account("acct_ok", 200)

        # Issuance snapshot errors
        with self.assertRaises(LookupError):
            self.db.issuance_snapshot("un_p", "https://auth.net", "pol")
        with self.assertRaises(LookupError):
            self.db.issuance_snapshot("usr_t", "https://unknown_i.net", "pol")
        with self.assertRaises(LookupError):
            self.db.issuance_snapshot("usr_t", "https://auth.net", "unknown_pol")

        # Bump epoch errors
        with self.assertRaises(LookupError):
            self.db.bump_principal_epoch("unknown_p", "session")
        with self.assertRaises(LookupError):
            self.db.bump_issuer_epoch("https://unknown_i.net")

        # Bump issuer epoch overflow
        conn = self.db.connect()
        conn.execute("UPDATE issuers SET issuer_epoch = ? WHERE issuer_digest = ?", (_uint64_to_blob(UINT64_MAX, "e"), self.issuer_digest))
        conn.commit()
        conn.close()
        with self.assertRaises(OverflowError):
            self.db.bump_issuer_epoch(self.issuer)

        # Balance lookup error
        with self.assertRaises(LookupError):
            self.db.balance("unknown_acct")

        # can_retire_key type check
        with self.assertRaises(TypeError):
            self.db.can_retire_key(b"short", 1700000000)

        # find_key_by_public_bytes & get_key_record_full
        k_id = self.cred_keyring.generate(self.issuer)
        pub_bytes = self.cred_keyring.export_public(k_id)
        found_id = self.db.find_key_by_public_bytes(pub_bytes)
        self.assertEqual(found_id, k_id)
        self.assertIsNone(self.db.find_key_by_public_bytes(b"x" * 32))

        rec_full = self.db.get_key_record_full(k_id)
        self.assertIsNotNone(rec_full)
        self.assertEqual(rec_full["status"], "active")
        self.assertIsNone(self.db.get_key_record_full(secrets.token_bytes(16)))

        # persist_key_record errors (altering immutable metadata & invalid DB transition)
        with self.assertRaises(ValueError):
            self.db.persist_key_record(k_id, b"y" * 32, KeyPurpose.CREDENTIAL_SIGNING, self.issuer_digest, KeyStatus.ACTIVE)
        with self.assertRaises(ValueError):
            self.db.persist_key_record(k_id, pub_bytes, KeyPurpose.CREDENTIAL_SIGNING, self.issuer_digest, KeyStatus.RETIRED)

        # Audit payload size limit & verify validation
        conn = self.db.connect()
        with self.assertRaises(ValueError):
            self.db.append_audit_log(conn, secrets.token_bytes(32), {"data": "x" * (MAX_AUDIT_PAYLOAD_BYTES + 100)})
        conn.close()

        with self.assertRaises(ValueError):
            self.db.verify_audit_log(b"short_key")
        self.assertFalse(self.db.verify_audit_log(secrets.token_bytes(32), "not a tuple")[0])
        self.assertFalse(self.db.verify_audit_log(secrets.token_bytes(32), (-1, secrets.token_bytes(32)))[0])
        self.assertFalse(self.db.verify_audit_log(secrets.token_bytes(32), (0, b"short"))[0])

    def test_keyring_cross_process_and_sync_branches(self):
        k_id = self.cred_keyring.generate(self.issuer)
        # Sign when DB status is verify_only
        self.db.persist_key_record(k_id, self.cred_keyring.export_public(k_id), KeyPurpose.CREDENTIAL_SIGNING, self.issuer_digest, KeyStatus.VERIFY_ONLY)
        with self.assertRaises(ValueError):
            self.cred_keyring.sign(k_id, b"payload", self.issuer_digest)

        # Sign when key deleted from DB
        ring_standalone = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        priv_bytes = ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fake_id = secrets.token_bytes(16)
        ring_standalone._records[fake_id] = KeyRecord(
            ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes).public_key(),
            ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes),
            KeyStatus.ACTIVE,
            KeyPurpose.CREDENTIAL_SIGNING,
            self.issuer_digest,
        )
        with self.assertRaises(ValueError):
            ring_standalone.sign(fake_id, b"payload", self.issuer_digest)

        # Verify reloading record from DB when not in memory
        verifier_ring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, self.db)
        valid_sig = ed25519.Ed25519PrivateKey.generate().sign(b"data")
        with self.assertRaises(AuthorizationRejected) as cm:
            verifier_ring.verify(k_id, b"data", valid_sig, self.issuer_digest)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_INVALID_SIGNATURE)

        # Verify key with database None and status retired
        none_db_ring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=None)
        none_k_id = none_db_ring.generate(self.issuer)
        none_db_ring.transition(none_k_id, KeyStatus.VERIFY_ONLY)
        none_db_ring.transition(none_k_id, KeyStatus.RETIRED)
        with self.assertRaises(AuthorizationRejected) as cm:
            none_db_ring.verify(none_k_id, b"data", valid_sig, self.issuer_digest)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_UNKNOWN_KEY)

        # Verify issuer mismatch on KeyRing
        active_k_id = self.cred_keyring.generate(self.issuer)
        active_sig = self.cred_keyring.sign(active_k_id, b"data", self.issuer_digest)
        with self.assertRaises(AuthorizationRejected) as cm:
            self.cred_keyring.verify(active_k_id, b"data", active_sig, b"w" * 32)
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_ISSUER_MISMATCH)

        # In-memory status is ACTIVE, DB status updated to VERIFY_ONLY -> verify syncs cache
        k_sync = self.cred_keyring.generate(self.issuer)
        conn = self.db.connect()
        conn.execute("UPDATE key_records SET status = 'verify_only' WHERE key_id = ?", (k_sync,))
        conn.commit()
        conn.close()
        sig_sync = ed25519.Ed25519PrivateKey.generate().sign(b"sync_data")
        with self.assertRaises(AuthorizationRejected):
            self.cred_keyring.verify(k_sync, b"sync_data", sig_sync, self.issuer_digest)
        self.assertEqual(self.cred_keyring._records[k_sync].status, KeyStatus.VERIFY_ONLY)
        self.assertIsNone(self.cred_keyring._records[k_sync].private_key)

    def test_legacy_database_migration_coverage(self):
        # 1. Corrupt balance migration error
        corrupt_db_path = os.path.join(self.tmp_dir.name, "corrupt_legacy.db")
        conn = sqlite3.connect(corrupt_db_path)
        conn.execute("PRAGMA user_version = 24;")
        conn.execute("CREATE TABLE accounts (account_id TEXT PRIMARY KEY, balance_minor INTEGER, version INTEGER);")
        conn.execute("INSERT INTO accounts VALUES ('bad_acct', -50, 1);")
        conn.commit()
        conn.close()
        with self.assertRaises(MigrationError):
            AuthorizationDatabase(corrupt_db_path)

        # 2. Legacy DB with receipt_signature but without receipt_key_id
        legacy_db_path1 = os.path.join(self.tmp_dir.name, "legacy1.db")
        conn = sqlite3.connect(legacy_db_path1)
        conn.execute("PRAGMA user_version = 24;")
        conn.execute("CREATE TABLE accounts (account_id TEXT PRIMARY KEY, balance_minor INTEGER, version INTEGER);")
        conn.execute("CREATE TABLE key_records (key_id BLOB PRIMARY KEY, public_key BLOB, purpose TEXT, issuer_digest BLOB, status TEXT);")
        conn.execute("""
            CREATE TABLE credential_results (
                credential_id BLOB PRIMARY KEY, token_digest BLOB, request_digest BLOB,
                result_payload BLOB, result_digest BLOB, receipt_signature BLOB,
                principal_digest BLOB, committed_at INTEGER, expires_at INTEGER
            );
        """)
        conn.execute("CREATE TABLE principals (principal_id TEXT PRIMARY KEY, packed_state BLOB);")
        conn.execute("CREATE TABLE issuers (issuer_digest BLOB PRIMARY KEY, issuer_epoch BLOB);")
        conn.execute("CREATE TABLE policies (policy_name TEXT PRIMARY KEY, policy_digest BLOB);")
        conn.execute("CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, previous_hash BLOB, event_hash BLOB, payload BLOB);")
        conn.commit()
        conn.close()
        migrated_db1 = AuthorizationDatabase(legacy_db_path1)
        c1 = migrated_db1.connect()
        self.assertEqual(c1.execute("PRAGMA user_version").fetchone()[0], 26)
        c1.close()

        # 3. Legacy DB with neither receipt_signature nor receipt_key_id
        legacy_db_path2 = os.path.join(self.tmp_dir.name, "legacy2.db")
        conn = sqlite3.connect(legacy_db_path2)
        conn.execute("PRAGMA user_version = 24;")
        conn.execute("CREATE TABLE accounts (account_id TEXT PRIMARY KEY, balance_minor INTEGER, version INTEGER);")
        conn.execute("CREATE TABLE key_records (key_id BLOB PRIMARY KEY, public_key BLOB, purpose TEXT, issuer_digest BLOB, status TEXT);")
        conn.execute("""
            CREATE TABLE credential_results (
                credential_id BLOB PRIMARY KEY, token_digest BLOB, request_digest BLOB,
                result_payload BLOB, result_digest BLOB,
                principal_digest BLOB, committed_at INTEGER, expires_at INTEGER
            );
        """)
        conn.execute("CREATE TABLE principals (principal_id TEXT PRIMARY KEY, packed_state BLOB);")
        conn.execute("CREATE TABLE issuers (issuer_digest BLOB PRIMARY KEY, issuer_epoch BLOB);")
        conn.execute("CREATE TABLE policies (policy_name TEXT PRIMARY KEY, policy_digest BLOB);")
        conn.execute("CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, previous_hash BLOB, event_hash BLOB, payload BLOB);")
        conn.commit()
        conn.close()
        migrated_db2 = AuthorizationDatabase(legacy_db_path2)
        c2 = migrated_db2.connect()
        self.assertEqual(c2.execute("PRAGMA user_version").fetchone()[0], 26)
        c2.close()

        # 4. Legacy DB with both receipt_signature and receipt_key_id
        legacy_db_path3 = os.path.join(self.tmp_dir.name, "legacy3.db")
        conn = sqlite3.connect(legacy_db_path3)
        conn.execute("PRAGMA user_version = 24;")
        conn.execute("CREATE TABLE accounts (account_id TEXT PRIMARY KEY, balance_minor INTEGER, version INTEGER);")
        conn.execute("CREATE TABLE key_records (key_id BLOB PRIMARY KEY, public_key BLOB, purpose TEXT, issuer_digest BLOB, status TEXT);")
        conn.execute("""
            CREATE TABLE credential_results (
                credential_id BLOB PRIMARY KEY, token_digest BLOB, request_digest BLOB,
                result_payload BLOB, result_digest BLOB, receipt_signature BLOB, receipt_key_id BLOB,
                principal_digest BLOB, committed_at INTEGER, expires_at INTEGER
            );
        """)
        conn.execute("CREATE TABLE principals (principal_id TEXT PRIMARY KEY, packed_state BLOB);")
        conn.execute("CREATE TABLE issuers (issuer_digest BLOB PRIMARY KEY, issuer_epoch BLOB);")
        conn.execute("CREATE TABLE policies (policy_name TEXT PRIMARY KEY, policy_digest BLOB);")
        conn.execute("CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, previous_hash BLOB, event_hash BLOB, payload BLOB);")
        conn.commit()
        conn.close()
        migrated_db3 = AuthorizationDatabase(legacy_db_path3)
        c3 = migrated_db3.connect()
        self.assertEqual(c3.execute("PRAGMA user_version").fetchone()[0], 26)
        c3.close()

    def test_database_rollback_on_error(self):
        class MockConn:
            def execute(self, *args, **kwargs):
                raise sqlite3.OperationalError("simulated db failure")
            def commit(self):
                pass
            def rollback(self):
                pass
            def close(self):
                pass

        with patch.object(self.db, "connect", return_value=MockConn()):
            with self.assertRaises(sqlite3.OperationalError):
                self.db.set_policy("rollback_pol", b'{"a": 1}')
            with self.assertRaises(sqlite3.OperationalError):
                self.db.purge_expired_receipts(1700000000)


class TestTGM5Vector5FastAPIAndEntrypoint(unittest.TestCase):
    """Vector 5: FastAPI Microservice Endpoints and Error Paths."""

    def test_app_cleanup(self):
        from src.api_service import AuthorizationServiceApp
        srv = AuthorizationServiceApp()
        srv.cleanup()
        self.assertFalse(os.path.exists(srv.db_path))
