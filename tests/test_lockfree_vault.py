"""
test_lockfree_vault.py — Unit & Boundary Coverage for LockFreeAtomicEpochVault
=============================================================================
"""

import secrets
import struct
import time
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.context_bound_epoch_protocol import (
    CredentialCodec,
    Ed25519KeyRing,
    KeyPurpose,
    pack_state,
    canonical_json_object,
)
from src.lockfree_memory_vault import (
    LockFreeAtomicEpochVault,
    FastZeroAllocValidator,
    PROTOCOL_VERSION,
    EXPECTED_TOKEN_SIZE,
    PAYLOAD_STRUCT,
)


class TestLockFreeMemoryVault(unittest.TestCase):
    def setUp(self):
        self.vault = LockFreeAtomicEpochVault(capacity=100)
        self.validator = FastZeroAllocValidator(self.vault)
        self.keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=None)
        self.issuer = "https://auth.enterprise.net"
        self.key_id = self.keyring.generate(self.issuer)
        self.codec = CredentialCodec(self.keyring, secrets.token_bytes(32), "us-east-prod")
        self.now = int(time.time())

    def test_01_register_and_validate_slot(self):
        state = pack_state(1, 1, 1, 1, 1)
        slot = self.vault.register_principal("user_1", state)
        self.assertEqual(slot, 0)
        self.assertEqual(self.vault.get_slot("user_1"), 0)
        self.assertEqual(self.vault.get_slot("nonexistent"), -1)
        self.assertTrue(self.vault.validate_epoch_fast(slot, state))
        self.assertFalse(self.vault.validate_epoch_fast(slot, state + 1))
        self.assertFalse(self.vault.validate_epoch_fast(-1, state))
        self.assertFalse(self.vault.validate_epoch_fast(999, state))

    def test_02_re_register_same_principal(self):
        state1 = pack_state(1, 1, 1, 1, 1)
        slot1 = self.vault.register_principal("user_reuse", state1)
        state2 = pack_state(2, 1, 1, 1, 1)
        slot2 = self.vault.register_principal("user_reuse", state2)
        self.assertEqual(slot1, slot2)
        self.assertTrue(self.vault.validate_epoch_fast(slot1, state2))

    def test_03_capacity_exhaustion(self):
        tiny_vault = LockFreeAtomicEpochVault(capacity=2)
        tiny_vault.register_principal("u1", 1)
        tiny_vault.register_principal("u2", 2)
        with self.assertRaises(RuntimeError):
            tiny_vault.register_principal("u3", 3)

    def test_04_atomic_invalidation(self):
        state = pack_state(1, 1, 1, 1, 1)
        slot = self.vault.register_principal("user_inv", state)
        new_val = self.vault.invalidate_epoch_atomic(slot, field_mask=12, increment=1)
        self.assertNotEqual(new_val, state)
        self.assertFalse(self.vault.validate_epoch_fast(slot, state))
        self.assertTrue(self.vault.validate_epoch_fast(slot, new_val))
        self.assertEqual(self.vault.invalidate_epoch_atomic(-1, 12), 0)

    def test_05_fast_validator_success(self):
        state = pack_state(10, 1, 1, 1, 1)
        slot = self.vault.register_principal("user_fast", state)
        req_bytes = canonical_json_object({"action": "read"})
        token = self.codec.issue(
            key_id=self.key_id,
            packed_state=state,
            issuer_epoch=0,
            issued_at=self.now,
            not_before=self.now,
            expires_at=self.now + 300,
            issuer=self.issuer,
            principal_id="user_fast",
            audience="https://api.net",
            resource="res",
            action="read",
            request_bytes=req_bytes,
            policy_digest=secrets.token_bytes(32),
        )

        ok, status = self.validator.fast_unpack_and_validate(token, self.now, slot)
        self.assertTrue(ok)
        self.assertEqual(status, "COMMIT_SUCCESS")

    def test_06_fast_validator_rejections(self):
        state = pack_state(10, 1, 1, 1, 1)
        slot = self.vault.register_principal("user_rej", state)
        req_bytes = canonical_json_object({"action": "read"})
        token = self.codec.issue(
            key_id=self.key_id,
            packed_state=state,
            issuer_epoch=0,
            issued_at=self.now,
            not_before=self.now + 10,
            expires_at=self.now + 300,
            issuer=self.issuer,
            principal_id="user_rej",
            audience="https://api.net",
            resource="res",
            action="read",
            request_bytes=req_bytes,
            policy_digest=secrets.token_bytes(32),
        )

        # 1. Malformed length
        ok, st = self.validator.fast_unpack_and_validate(b"short", self.now, slot)
        self.assertFalse(ok)
        self.assertEqual(st, "REJECT_MALFORMED_PAYLOAD")

        # 2. Version mismatch
        bad_ver = bytearray(token)
        bad_ver[0] = 0x99
        ok, st = self.validator.fast_unpack_and_validate(bytes(bad_ver), self.now, slot)
        self.assertFalse(ok)
        self.assertEqual(st, "REJECT_VERSION_MISMATCH")

        # 3. Not yet valid
        ok, st = self.validator.fast_unpack_and_validate(token, self.now, slot)
        self.assertFalse(ok)
        self.assertEqual(st, "REJECT_NOT_YET_VALID")

        # 4. Expired
        ok, st = self.validator.fast_unpack_and_validate(token, self.now + 500, slot)
        self.assertFalse(ok)
        self.assertEqual(st, "REJECT_EXPIRED")

        # 5. State mismatch
        self.vault.invalidate_epoch_atomic(slot, field_mask=12, increment=1)
        ok, st = self.validator.fast_unpack_and_validate(token, self.now + 20, slot)
        self.assertFalse(ok)
        self.assertEqual(st, "REJECT_STATE_MISMATCH")


if __name__ == "__main__":
    unittest.main()
