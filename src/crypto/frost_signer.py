"""Experimental threshold-signing scaffold; no cryptographically valid FROST signatures are produced."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
import hashlib
import secrets

L = 2**252 + 27742317777372353535851937790883648493

def _hash_to_scalar(*parts: bytes) -> int:
    h = hashlib.sha512(b"".join(parts)).digest()
    return int.from_bytes(h, "little") % L

def _lagrange_coefficient(i: int, signers: Set[int]) -> int:
    """Computes λ_i = ∏_{j ∈ 𝒮, j ≠ i} j * (j - i)^(-1) mod ℓ."""
    num = 1
    den = 1
    for j in signers:
        if j == i:
            continue
        num = (num * j) % L
        diff = (j - i) % L
        den = (den * diff) % L
    return (num * pow(den, L - 2, L)) % L

@dataclass
class NonceCommitment:
    node_id: int
    D: bytes
    E: bytes

@dataclass
class SigningShare:
    node_id: int
    z: int

@dataclass
class FROSTSignature:
    R: bytes
    S: bytes

    def to_bytes(self) -> bytes:
        return self.R + self.S  # 64-byte canonical Ed25519

class FROSTParticipant:
    def __init__(self, node_id: int, secret_share: int, verification_share: bytes):
        self.id = node_id
        self.s = secret_share
        self.Y = verification_share
        self.d: Optional[int] = None
        self.e: Optional[int] = None
        self.D: Optional[bytes] = None
        self.E: Optional[bytes] = None

    def round1_nonce(self) -> NonceCommitment:
        self.d = secrets.randbelow(L - 1) + 1
        self.e = secrets.randbelow(L - 1) + 1
        self.D = hashlib.sha256(b"NONCE_D" + self.d.to_bytes(32, "little")).digest()
        self.E = hashlib.sha256(b"NONCE_E" + self.e.to_bytes(32, "little")).digest()
        return NonceCommitment(self.id, self.D, self.E)

    def round2_sign(
        self,
        message: bytes,
        commitments: Dict[int, NonceCommitment],
        signers: Set[int],
        group_public_key: bytes,
    ) -> SigningShare:
        raise NotImplementedError("threshold signing is disabled until real Ed25519 group operations are implemented")

def frost_coordinate(
    participants: List[FROSTParticipant],
    message: bytes,
    group_public_key: bytes,
    t: int,
) -> FROSTSignature:
    """Raises rather than emitting a 64-byte value that only resembles a signature."""
    raise NotImplementedError("threshold signing is disabled until real Ed25519 group operations are implemented")
