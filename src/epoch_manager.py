"""
ZKAEDI Epoch Manager — Quorum-Signed Monotonic Epoch Invalidation Engine
Requires a (t, n) FROST threshold signature to advance any issuer epoch.
Zero unilateral advancement. Enforces SQLite STRICT triggers & linearizable receipts.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple, List
import hashlib
import time
import sqlite3

from .crypto.frost_signer import FROSTSignature, frost_coordinate, FROSTParticipant
from .crypto.dkg import DKGTranscript

@dataclass
class EpochAdvanceRequest:
    issuer_id: str
    current_epoch: int
    target_epoch: int
    state_root: bytes
    timestamp: int = field(default_factory=lambda: int(time.time()))

@dataclass
class EpochCertificate:
    issuer_id: str
    epoch: int
    state_root: bytes
    signature: FROSTSignature
    signer_ids: Set[int]
    issued_at: int

    def message(self) -> bytes:
        return b"EPOCH_ADVANCE" + self.issuer_id.encode() + \
               self.epoch.to_bytes(8, "big") + self.state_root

class EpochManager:
    def __init__(self, transcript: DKGTranscript, t: int, db_path: str = ":memory:"):
        self.transcript = transcript
        self.t = t
        self.group_pk = transcript.group_public_key
        assert self.group_pk is not None
        assert len(transcript.qual) >= t

        self.db = sqlite3.connect(db_path)
        self._init_strict_schema()

    def _init_strict_schema(self):
        cur = self.db.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS threshold_epoch_proofs (
            issuer_id TEXT NOT NULL,
            epoch_number INTEGER NOT NULL CHECK(epoch_number > 0),
            state_root_hash BLOB NOT NULL,
            quorum_signature BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (issuer_id, epoch_number)
        ) STRICT;

        CREATE TRIGGER IF NOT EXISTS trg_prevent_epoch_rollback
        BEFORE INSERT ON threshold_epoch_proofs
        FOR EACH ROW
        BEGIN
            SELECT CASE
                WHEN NEW.epoch_number <= (
                    SELECT COALESCE(MAX(epoch_number), 0)
                    FROM threshold_epoch_proofs
                    WHERE issuer_id = NEW.issuer_id
                )
                THEN RAISE(ABORT, 'REJECT: Non-monotonic epoch advancement strictly prohibited')
            END;
        END;
        """)
        self.db.commit()

    def request_advance(
        self,
        req: EpochAdvanceRequest,
        participants: List[FROSTParticipant],
    ) -> EpochCertificate:
        raise NotImplementedError(
            "threshold epoch advancement is disabled: the bundled threshold signer is not cryptographically verified"
        )

    def verify_certificate(self, cert: EpochCertificate) -> bool:
        """Verifies an Ed25519 certificate under the configured group public key."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            Ed25519PublicKey.from_public_bytes(self.group_pk).verify(
                cert.signature.to_bytes(), cert.message()
            )
        except (InvalidSignature, ValueError):
            return False
        return True
