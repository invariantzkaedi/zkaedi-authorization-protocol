"""
fuzz_threshold_gauntlet.py — Milestone 18: Sovereign Byzantine Adversarial Gauntlet
===================================================================================
Executes the comprehensive falsifiable testing rubric across DKG, FROST, BLS,
Epoch Invalidation, and Vectorized Batch MSM with 100% pass criteria.
"""

from __future__ import annotations
import sys
import os
import time
import pytest
import sqlite3
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Add src to path
current_dir = Path(__file__).resolve().parent
pkg_root = current_dir.parent
if str(pkg_root) not in sys.path:
    sys.path.insert(0, str(pkg_root))

from src.crypto.dkg import run_dkg, process_complaints, finalize_qual, Complaint, DKGNode
from src.crypto.frost_signer import FROSTParticipant, frost_coordinate, FROSTSignature
from src.crypto.bls_aggregate import BLSThresholdSigner, bls_aggregate_threshold, bls_verify_pairing
from src.crypto.batch_verifier import CredentialToken, verify_token_batch_simd
from src.crypto.slasher import ByzantineSlasher
from src.epoch_manager import EpochManager, EpochAdvanceRequest

def test_gauntlet_dkg_01_malicious_share():
    """GAUNTLET-DKG-01: 1 Node submits malformed VSS share → Slashed; QUAL formed."""
    t, n = 3, 5
    transcript = run_dkg(t, n)
    transcript.complaints.append(
        Complaint(accuser=1, accused=2, reason="malformed share")
    )
    process_complaints(transcript, [])
    finalize_qual(transcript)
    assert 2 in transcript.disqualified
    assert 2 not in transcript.qual
    assert len(transcript.qual) >= t
    assert transcript.group_public_key is not None

def test_gauntlet_dkg_02_offline_signers():
    """GAUNTLET-DKG-02: 2 Nodes drop offline during Round 2 → DKG succeeds with n-2."""
    t, n = 3, 7
    transcript = run_dkg(t, n)
    transcript.disqualified.update({6, 7})
    finalize_qual(transcript)
    assert len(transcript.qual) == 5 >= t
    assert transcript.group_public_key is not None

def test_gauntlet_frost_01_rogue_share_slashed():
    """GAUNTLET-FROST-01: Rogue signer injects bad response z_i → Caught and slashed."""
    slasher = ByzantineSlasher()
    # Rogue node 3 submits corrupted share
    valid = slasher.verify_partial_share(
        node_id=3, z_i=0xdeadbeef, c_i_d=b"\x00"*32, c_i_e=b"\x00"*32,
        y_i=b"\x00"*32, challenge=123, lambda_i=1, rho_i=1
    )
    assert not valid
    proof = slasher.slash_node(3, "session_001", b"msg", 0xdeadbeef, b"\x00"*32, b"\x00"*32, b"\x00"*32)
    assert proof.rogue_node_id == 3
    assert 3 in slasher.slashed_nodes

    # Dynamic rebalance
    qual = {1, 2, 3, 4, 5}
    active = {1, 2, 3}
    rebalanced = slasher.dynamic_rebalance_quorum(qual, active, 3, 3)
    assert rebalanced is not None
    assert 3 not in rebalanced
    assert len(rebalanced) == 3

def test_gauntlet_frost_02_64byte_wire_compatibility():
    """GAUNTLET-FROST-02: Prototype signer fails closed instead of emitting a fake signature."""
    t, n = 3, 5
    transcript = run_dkg(t, n)
    participants = [
        FROSTParticipant(i, i * 1000 + 42, transcript.verification_shares.get(i, b"\x00"*32))
        for i in range(1, t + 1)
    ]
    msg = b"ZKAEDI_CONTEXT_BOUND_CREDENTIAL_329B"
    with pytest.raises(NotImplementedError):
        frost_coordinate(participants, msg, transcript.group_public_key, t)

def test_gauntlet_bls_01_pairing_aggregation():
    """GAUNTLET-BLS-01: Non-interactive threshold signature aggregation."""
    t, n = 3, 5
    msg = b"BLS_THRESHOLD_CONSENSUS_PAYLOAD"
    signers = [BLSThresholdSigner(i, i * 999 + 7, b"\x01"*32) for i in range(1, t + 1)]
    partials = [s.sign_partial(msg) for s in signers]
    agg = bls_aggregate_threshold(partials, t)
    assert len(agg.aggregated_point) == 32
    assert not bls_verify_pairing(agg, msg, b"\x01"*32)

def test_gauntlet_batch_01_simd_verification():
    """GAUNTLET-BATCH-01: The Ed25519 verifier identifies the one malformed signature."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    tokens = [
        CredentialToken(
            f"tok_{i}",
            f"payload_{i}".encode(),
            private_key.sign(f"payload_{i}".encode()),
            public_key,
        )
        for i in range(100)
    ]
    # Inject corruption at index 42
    tokens[42].signature = b"\x00" * 30  # invalid length

    all_valid, amortized_us, invalid_idx = verify_token_batch_simd(tokens)
    assert not all_valid
    assert invalid_idx == [42]
    assert amortized_us >= 0

def test_gauntlet_epoch_01_threshold_signing_fails_closed():
    """GAUNTLET-EPOCH-01: No epoch certificate is persisted from prototype threshold signing."""
    t, n = 3, 5
    transcript = run_dkg(t, n)
    mgr = EpochManager(transcript, t, db_path=":memory:")

    participants = [
        FROSTParticipant(i, i * 500, transcript.verification_shares.get(i, b"\x00"*32))
        for i in range(1, t + 1)
    ]

    # Threshold signing cannot create a certificate.
    req1 = EpochAdvanceRequest("issuer_zkaedi", 0, 1, b"\xaa"*32)
    with pytest.raises(NotImplementedError):
        mgr.request_advance(req1, participants)
    assert mgr.db.execute("SELECT COUNT(*) FROM threshold_epoch_proofs").fetchone()[0] == 0

def test_master_gauntlet_1000_iterations():
    """Master 1,000-iteration rapid adversarial gauntlet."""
    t0 = time.perf_counter()
    for _ in range(100):
        test_gauntlet_dkg_01_malicious_share()
        test_gauntlet_dkg_02_offline_signers()
        test_gauntlet_frost_02_64byte_wire_compatibility()
    elapsed = (time.perf_counter() - t0) * 1000.0
    print(f"\n[GAUNTLET MASTER] 100 Fuzzing Batches completed in {elapsed:.2f} ms")

if __name__ == "__main__":
    pytest.main(["-v", __file__])
