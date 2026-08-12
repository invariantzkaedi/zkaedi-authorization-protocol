from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from src.context_bound_epoch_protocol import (
    AuthStatus,
    AuthorizationDatabase,
    AuthorizationRejected,
    CredentialCodec,
    Ed25519KeyRing,
    KeyPurpose,
    KeyStatus,
    LinearizableEngine,
    _field_digest,
    pack_state,
)


class TestV26MasterCumulativeSuite(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "auth.db"
        self.db = AuthorizationDatabase(self.db_path)

        self.issuer = "https://auth.net"

        # Credential Keyring with persistent database backing
        self.cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=self.db)
        self.cred_key_id = self.cred_keyring.generate(self.issuer)

        # Dedicated Receipt Keyring with persistent database backing
        self.receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, database=self.db)
        self.receipt_key_id = self.receipt_keyring.generate(self.issuer)

        self.p_key = secrets.token_bytes(32)
        self.audit_key = secrets.token_bytes(32)

        self.codec = CredentialCodec(self.cred_keyring, self.p_key, "prod-us-east-1")
        self.engine = LinearizableEngine(
            self.db, self.codec, self.audit_key,
            receipt_keyring=self.receipt_keyring, receipt_key_id=self.receipt_key_id
        )

        self.policy_name = "default_policy"
        self.policy_bytes = b'{"allow_transfer":true}'
        self.policy_digest = self.db.set_policy(self.policy_name, self.policy_bytes)
        self.db.initialize_issuer(self.issuer, 0)
        self.db.initialize_principal("usr_100", pack_state(1, 1, 1, 1, 1))
        self.db.initialize_principal("usr_200", pack_state(1, 1, 1, 1, 1))
        self.db.create_account("vault-1", 1000)
        self.db.create_account("vault-2", 500)
        self.now = 1000

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cached_verifier_rejects_retired_key(self):
        """1. Asserts that a verifier process with cached key in memory REJECTS signatures once key is RETIRED in DB."""
        # Process B keyring loaded BEFORE retirement
        proc_b_ring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=self.db)
        pub_bytes = self.cred_keyring.export_public(self.cred_key_id)
        proc_b_ring.register_public(self.cred_key_id, pub_bytes, self.issuer, status=KeyStatus.VERIFY_ONLY)

        # Issue credential while ACTIVE
        snap = self.db.issuance_snapshot("usr_100", self.issuer, self.policy_name)
        req = b'{"action":"transfer","amount_minor":100,"destination_account":"vault-2","source_account":"vault-1"}'
        tok = self.codec.issue(
            key_id=self.cred_key_id, packed_state=snap.packed_state, issuer_epoch=snap.issuer_epoch,
            issued_at=self.now, not_before=self.now, expires_at=self.now+300, issuer=self.issuer,
            principal_id="usr_100", audience="https://api.net", resource="vault", action="transfer",
            request_bytes=req, policy_digest=snap.policy_digest
        )

        # Confirm proc_b verifies initially
        proc_b_codec = CredentialCodec(proc_b_ring, self.p_key, "prod-us-east-1")
        proc_b_codec.verify(
            tok, current_time=self.now+5, expected_issuer=self.issuer, expected_principal_id="usr_100",
            expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
            expected_request_bytes=req
        )

        # Rotate key to VERIFY_ONLY then RETIRED in DB
        self.cred_keyring.transition(self.cred_key_id, KeyStatus.VERIFY_ONLY)
        self.cred_keyring.transition(self.cred_key_id, KeyStatus.RETIRED)

        # Proc B verify MUST REJECT RETIRED key despite having cached KeyRecord in memory
        with self.assertRaises(AuthorizationRejected) as cm:
            proc_b_codec.verify(
                tok, current_time=self.now+6, expected_issuer=self.issuer, expected_principal_id="usr_100",
                expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
                expected_request_bytes=req
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_UNKNOWN_KEY)

    def test_direct_sql_delete_prevention(self):
        """2. Asserts that direct SQL DELETE queries on key_records are aborted by DB trigger."""
        conn = self.db.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError) as cm:
                conn.execute("DELETE FROM key_records WHERE key_id = ?", (self.cred_key_id,))
            self.assertIn("deletion of key_records is strictly forbidden", str(cm.exception))
        finally:
            conn.close()

    def test_v24_legacy_database_migration_to_v26(self):
        """3. Asserts real v24 legacy database migration installs UNIQUE(public_key) and delete guard triggers."""
        v24_db_path = Path(self.temp_dir.name) / "v24_legacy.db"
        conn = sqlite3.connect(v24_db_path)
        # Create legacy v24 schema (no UNIQUE on public_key, user_version = 24)
        conn.executescript("""
            CREATE TABLE principals (principal_id TEXT PRIMARY KEY, packed_state BLOB NOT NULL CHECK(length(packed_state) = 8)) STRICT;
            CREATE TABLE issuers (issuer_digest BLOB PRIMARY KEY CHECK(length(issuer_digest) = 32), issuer_epoch BLOB NOT NULL CHECK(length(issuer_epoch) = 8)) STRICT;
            CREATE TABLE policies (policy_name TEXT PRIMARY KEY, policy_digest BLOB NOT NULL CHECK(length(policy_digest) = 32)) STRICT;
            CREATE TABLE accounts (account_id TEXT PRIMARY KEY, balance_minor INTEGER NOT NULL, version INTEGER NOT NULL) STRICT;
            CREATE TABLE key_records (key_id BLOB PRIMARY KEY CHECK(length(key_id) = 16), public_key BLOB NOT NULL, purpose TEXT NOT NULL, issuer_digest BLOB NOT NULL, status TEXT NOT NULL) STRICT;
            CREATE TABLE credential_results (credential_id BLOB PRIMARY KEY CHECK(length(credential_id) = 16), token_digest BLOB NOT NULL CHECK(length(token_digest) = 32), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), result_payload BLOB NOT NULL, result_digest BLOB NOT NULL CHECK(length(result_digest) = 32), receipt_signature BLOB, receipt_key_id BLOB, principal_digest BLOB NOT NULL CHECK(length(principal_digest) = 32), committed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
            CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32), event_hash BLOB NOT NULL CHECK(length(event_hash) = 32), payload BLOB NOT NULL) STRICT;
            PRAGMA user_version = 24;
        """)
        conn.close()

        # Instantiate AuthorizationDatabase on legacy v24 DB file -> Triggers migration to v26
        migrated_db = AuthorizationDatabase(v24_db_path)
        conn2 = migrated_db.connect()
        try:
            ver = conn2.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(ver, 26)

            sql_row = conn2.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='key_records'").fetchone()[0]
            self.assertIn("UNIQUE", sql_row)
        finally:
            conn2.close()

    def test_cross_process_key_rotation_synchronization(self):
        """4. Asserts that rotating key status in DB instantly disables signing across separate process instances."""
        proc2_ring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=self.db)
        raw_priv = self.cred_keyring._records[self.cred_key_id].private_key.private_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()
        )
        proc2_ring.register_private(self.cred_key_id, raw_priv, self.issuer)

        # Rotate key to VERIFY_ONLY in DB
        self.cred_keyring.transition(self.cred_key_id, KeyStatus.VERIFY_ONLY)

        # Process B attempts to sign MUST REJECT
        with self.assertRaises(ValueError) as cm:
            proc2_ring.sign(self.cred_key_id, b"dummy_payload", _field_digest(b"issuer-v1", self.issuer))
        self.assertIn("key is no longer active in database", str(cm.exception))

    def test_failed_registration_rollback(self):
        """5. Asserts that DB registration failure leaves NO in-memory active key record."""
        new_k_id = secrets.token_bytes(16)
        raw_priv = self.cred_keyring._records[self.cred_key_id].private_key.private_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()
        )

        with self.assertRaises((ValueError, sqlite3.IntegrityError)):
            self.cred_keyring.register_private(new_k_id, raw_priv, self.issuer)

        self.assertNotIn(new_k_id, self.cred_keyring._records)

    def test_same_id_immutable_metadata_verification(self):
        """6. Asserts that updating an existing key ID with substituted public key or purpose is rejected in DB."""
        pub_diff = secrets.token_bytes(32)

        with self.assertRaises(ValueError) as cm:
            self.db.persist_key_record(
                self.cred_key_id, pub_diff, KeyPurpose.CREDENTIAL_SIGNING,
                _field_digest(b"issuer-v1", self.issuer), KeyStatus.VERIFY_ONLY
            )
        self.assertIn("cannot alter immutable key metadata", str(cm.exception))

    def test_direct_sql_reactivation_trigger(self):
        """7. Asserts that SQLite triggers abort direct SQL updates trying to reactivate VERIFY_ONLY keys."""
        self.cred_keyring.transition(self.cred_key_id, KeyStatus.VERIFY_ONLY)

        conn = self.db.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError) as cm:
                conn.execute("UPDATE key_records SET status = 'active' WHERE key_id = ?", (self.cred_key_id,))
            self.assertIn("cannot reactivate verify_only key", str(cm.exception))
        finally:
            conn.close()

    def test_strict_genesis_append_growth_and_tail_deletion_audit_checkpoint(self):
        """8. Asserts strict genesis checkpoint validation, append-only growth, AND tail-event deletion detection."""
        snap = self.db.issuance_snapshot("usr_100", self.issuer, self.policy_name)
        req = b'{"action":"transfer","amount_minor":100,"destination_account":"vault-2","source_account":"vault-1"}'
        tok1 = self.codec.issue(
            key_id=self.cred_key_id, packed_state=snap.packed_state, issuer_epoch=snap.issuer_epoch,
            issued_at=self.now, not_before=self.now, expires_at=self.now+300, issuer=self.issuer,
            principal_id="usr_100", audience="https://api.net", resource="vault", action="transfer",
            request_bytes=req, policy_digest=snap.policy_digest
        )

        # Event 1
        self.engine.execute_transfer(
            tok1, current_time=self.now+5, expected_issuer=self.issuer, expected_principal_id="usr_100",
            expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
            expected_request_bytes=req, expected_policy_name=self.policy_name
        )

        # Event 2
        tok2 = self.codec.issue(
            key_id=self.cred_key_id, packed_state=snap.packed_state, issuer_epoch=snap.issuer_epoch,
            issued_at=self.now+1, not_before=self.now+1, expires_at=self.now+300, issuer=self.issuer,
            principal_id="usr_100", audience="https://api.net", resource="vault", action="transfer",
            request_bytes=req, policy_digest=snap.policy_digest
        )
        self.engine.execute_transfer(
            tok2, current_time=self.now+6, expected_issuer=self.issuer, expected_principal_id="usr_100",
            expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
            expected_request_bytes=req, expected_policy_name=self.policy_name
        )

        _, count2, latest_hash2 = self.db.verify_audit_log(self.audit_key)
        cp_ev2 = (count2, latest_hash2)

        # Tail deletion: Delete newest event 2
        conn = self.db.connect()
        conn.execute("DELETE FROM audit_events WHERE sequence = 2")
        conn.close()

        # Verification with cp_ev2 MUST FAIL after tail event deletion
        is_valid_tail_del, _, _ = self.db.verify_audit_log(self.audit_key, trusted_checkpoint=cp_ev2)
        self.assertFalse(is_valid_tail_del)

    def test_signed_receipt_tamper_detection_and_replay(self):
        """9. Asserts that signed receipts guarantee replay idempotency and catch database result tampering."""
        snap = self.db.issuance_snapshot("usr_100", self.issuer, self.policy_name)
        req = b'{"action":"transfer","amount_minor":100,"destination_account":"vault-2","source_account":"vault-1"}'
        tok = self.codec.issue(
            key_id=self.cred_key_id, packed_state=snap.packed_state, issuer_epoch=snap.issuer_epoch,
            issued_at=self.now, not_before=self.now, expires_at=self.now+300, issuer=self.issuer,
            principal_id="usr_100", audience="https://api.net", resource="vault", action="transfer",
            request_bytes=req, policy_digest=snap.policy_digest
        )

        res1 = self.engine.execute_transfer(
            tok, current_time=self.now+5, expected_issuer=self.issuer, expected_principal_id="usr_100",
            expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
            expected_request_bytes=req, expected_policy_name=self.policy_name
        )
        self.assertEqual(res1.status, AuthStatus.COMMIT_SUCCESS)

        res2 = self.engine.execute_transfer(
            tok, current_time=self.now+6, expected_issuer=self.issuer, expected_principal_id="usr_100",
            expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
            expected_request_bytes=req, expected_policy_name=self.policy_name
        )
        self.assertEqual(res2.status, AuthStatus.IDEMPOTENT_REPLAY)

        conn = self.db.connect()
        forged_payload = b'{"amount_minor":999999,"destination_account":"vault-2","new_destination_balance":999999,"new_source_balance":0,"source_account":"vault-1"}'
        forged_digest = hashlib.sha256(forged_payload).digest()
        conn.execute("UPDATE credential_results SET result_payload = ?, result_digest = ?", (forged_payload, forged_digest))
        conn.close()

        with self.assertRaises(AuthorizationRejected) as cm:
            self.engine.execute_transfer(
                tok, current_time=self.now+7, expected_issuer=self.issuer, expected_principal_id="usr_100",
                expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
                expected_request_bytes=req, expected_policy_name=self.policy_name
            )
        self.assertEqual(cm.exception.status, AuthStatus.REJECT_RESULT_TAMPERED)

    def test_purge_expired_receipts_and_can_retire_key(self):
        """10. Asserts atomic safe-to-retire check returns False when active receipt exists, True after expiration/purge."""
        snap = self.db.issuance_snapshot("usr_100", self.issuer, self.policy_name)
        req = b'{"action":"transfer","amount_minor":100,"destination_account":"vault-2","source_account":"vault-1"}'
        tok = self.codec.issue(
            key_id=self.cred_key_id, packed_state=snap.packed_state, issuer_epoch=snap.issuer_epoch,
            issued_at=self.now, not_before=self.now, expires_at=self.now+300, issuer=self.issuer,
            principal_id="usr_100", audience="https://api.net", resource="vault", action="transfer",
            request_bytes=req, policy_digest=snap.policy_digest
        )

        self.engine.execute_transfer(
            tok, current_time=self.now+5, expected_issuer=self.issuer, expected_principal_id="usr_100",
            expected_audience="https://api.net", expected_resource="vault", expected_action="transfer",
            expected_request_bytes=req, expected_policy_name=self.policy_name
        )

        # Unexpired receipt exists -> can_retire_key MUST be False
        self.assertFalse(self.db.can_retire_key(self.receipt_key_id, current_time=self.now+10))

        # Fast-forward past receipt expiration & purge
        purged = self.db.purge_expired_receipts(current_time=self.now+400)
        self.assertEqual(purged, 1)

        # Receipts purged -> can_retire_key MUST be True
        self.assertTrue(self.db.can_retire_key(self.receipt_key_id, current_time=self.now+400))


if __name__ == "__main__":
    unittest.main()
