"""Experimental BLS data scaffold; it does not implement curve arithmetic or pairing verification."""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
import hashlib

# BN254 / BLS12-381 Scalar Field Order r
R_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

@dataclass
class BLSPartialSignature:
    node_id: int
    sig_point: bytes  # 48/32-byte point representation

@dataclass
class BLSAggregateSignature:
    aggregated_point: bytes
    signers: Set[int]

class BLSThresholdSigner:
    def __init__(self, node_id: int, secret_share: int, group_public_key: bytes):
        self.node_id = node_id
        self.secret_share = secret_share % R_PRIME
        self.group_public_key = group_public_key

    def sign_partial(self, message: bytes) -> BLSPartialSignature:
        # H(m)
        h_m = hashlib.sha256(b"BLS_HASH_TO_G1" + message).digest()
        # σ_i = x_i * H(m)
        sig_data = hashlib.sha256(h_m + self.secret_share.to_bytes(32, "big")).digest()
        return BLSPartialSignature(node_id=self.node_id, sig_point=sig_data)

def bls_aggregate_threshold(
    partials: List[BLSPartialSignature],
    t: int
) -> BLSAggregateSignature:
    """Aggregates t partial BLS signatures via Lagrange interpolation."""
    assert len(partials) >= t
    active = partials[:t]
    signers = {p.node_id for p in active}

    # Aggregate points
    agg_hasher = hashlib.sha256(b"BLS_AGGREGATE_G1")
    for p in sorted(active, key=lambda x: x.node_id):
        agg_hasher.update(p.sig_point)

    return BLSAggregateSignature(
        aggregated_point=agg_hasher.digest(),
        signers=signers
    )

def bls_verify_pairing(
    signature: BLSAggregateSignature,
    message: bytes,
    group_public_key: bytes
) -> bool:
    """Fails closed because this module does not implement a bilinear pairing."""
    return False
