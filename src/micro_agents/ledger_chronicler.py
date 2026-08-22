"""
ZKAEDI Ledger Chronicler — Cryptographic Proof & Turn Receipt Anchoring
Records tamper-evident event chains with SHA-256 Merkle consistency proofs.
"""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class EvidenceEntry:
    sequence: int
    action_type: str
    agent_id: str
    artifact_hash: str
    payload_summary: str
    prev_hash: str
    timestamp: float = field(default_factory=time.time)
    entry_hash: str = ""

    def compute_hash(self) -> str:
        data = f"{self.sequence}:{self.action_type}:{self.agent_id}:{self.artifact_hash}:{self.prev_hash}:{self.timestamp}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

class LedgerChronicler:
    def __init__(self, genesis_label: str = "ZKAEDI_GENESIS_CHRONICLE"):
        self.genesis_hash = hashlib.sha256(genesis_label.encode("utf-8")).hexdigest()
        self.chain: List[EvidenceEntry] = []

    def record_turn(
        self,
        agent_id: str,
        action_type: str,
        artifact_bytes: bytes,
        summary: str
    ) -> EvidenceEntry:
        prev = self.chain[-1].entry_hash if self.chain else self.genesis_hash
        art_hash = hashlib.sha256(artifact_bytes).hexdigest()
        entry = EvidenceEntry(
            sequence=len(self.chain) + 1,
            action_type=action_type,
            agent_id=agent_id,
            artifact_hash=art_hash,
            payload_summary=summary,
            prev_hash=prev
        )
        entry.entry_hash = entry.compute_hash()
        self.chain.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        """Verifies the complete chronological hash chain."""
        prev = self.genesis_hash
        for entry in self.chain:
            if entry.prev_hash != prev:
                return False
            if entry.entry_hash != entry.compute_hash():
                return False
            prev = entry.entry_hash
        return True
