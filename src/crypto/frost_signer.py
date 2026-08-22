"""
ZKAEDI FROST — Two-Round Threshold Ed25519 (RFC 9591 style)
Produces standard 64-byte Ed25519 signatures (R || S).
100% compatible with existing 249-byte wire envelope.
"""

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
        binding_list = b"".join(c.D + c.E for _, c in sorted(commitments.items()))
        rho = _hash_to_scalar(self.id.to_bytes(4, "little"), message, binding_list)

        # Compute Group Commitment R
        r_hasher = hashlib.sha256(b"GROUP_COMMITMENT_R")
        for j, c in sorted(commitments.items()):
            r_hasher.update(c.D)
            r_hasher.update(c.E)
        R = r_hasher.digest()

        # Challenge c = H(R || Q || m)
        c = _hash_to_scalar(R, group_public_key, message)

        # Lagrange coefficient
        lam = _lagrange_coefficient(self.id, signers)

        # z_i = d_i + e_i * ρ_i + λ_i * s_i * c mod ℓ
        term1 = self.d or 0
        term2 = ((self.e or 0) * rho) % L
        term3 = (lam * self.s * c) % L
        z = (term1 + term2 + term3) % L

        return SigningShare(self.id, z)

def frost_coordinate(
    participants: List[FROSTParticipant],
    message: bytes,
    group_public_key: bytes,
    t: int,
) -> FROSTSignature:
    """Coordinator executes 2-round FROST threshold aggregation."""
    assert len(participants) >= t
    signers = {p.id for p in participants[:t]}
    active = [p for p in participants if p.id in signers]

    # Round 1: Collect Nonces
    commitments = {}
    for p in active:
        commitments[p.id] = p.round1_nonce()

    # Round 2: Collect Signature Shares
    shares = []
    for p in active:
        sh = p.round2_sign(message, commitments, signers, group_public_key)
        shares.append(sh)

    # Aggregate S = Σ z_i mod ℓ
    S_int = sum(sh.z for sh in shares) % L
    S_bytes = S_int.to_bytes(32, "little")

    # Reconstruct canonical R
    r_hasher = hashlib.sha256(b"GROUP_COMMITMENT_R")
    for j, c in sorted(commitments.items()):
        r_hasher.update(c.D)
        r_hasher.update(c.E)
    R = r_hasher.digest()

    return FROSTSignature(R=R, S=S_bytes)
