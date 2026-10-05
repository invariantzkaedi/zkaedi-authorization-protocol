"""Straightforward per-token Ed25519 verification; this is not SIMD or aggregate verification."""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

@dataclass
class CredentialToken:
    token_id: str
    message: bytes
    signature: bytes  # 64-byte Ed25519
    public_key: bytes # 32-byte group public key

def verify_token_batch_simd(tokens: List[CredentialToken]) -> Tuple[bool, float, List[int]]:
    """
    Verifies each token independently with the cryptography library's Ed25519 verifier.
    Returns (all_valid, amortized_latency_us, invalid_indices).
    """
    if not tokens:
        return True, 0.0, []

    t0 = time.perf_counter_ns()
    k = len(tokens)
    invalid_indices = []

    for i, tok in enumerate(tokens):
        if len(tok.signature) != 64 or len(tok.public_key) != 32:
            invalid_indices.append(i)
            continue
        try:
            Ed25519PublicKey.from_public_bytes(tok.public_key).verify(tok.signature, tok.message)
        except (InvalidSignature, ValueError):
            invalid_indices.append(i)

    t1 = time.perf_counter_ns()
    elapsed_us = (t1 - t0) / 1000.0
    amortized_us = elapsed_us / k if k > 0 else 0.0

    all_valid = not invalid_indices
    return all_valid, amortized_us, invalid_indices
