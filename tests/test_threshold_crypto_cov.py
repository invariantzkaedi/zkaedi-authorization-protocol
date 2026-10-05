"""
test_threshold_crypto_cov.py — 100% Branch-Aware Coverage Suite for src/crypto & src/epoch_manager
==================================================================================================
Covers every branch, edge condition, exception path, and mathematical helper in the threshold suite.
"""

import pytest
import sqlite3
from typing import Set
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.crypto.dkg import (
    _random_scalar, _scalar_to_bytes, _bytes_to_scalar, _scalar_mul_base,
    DKGNode, DKGTranscript, Commitment, Share, Complaint,
    process_complaints, finalize_qual, run_dkg, L
)
from src.crypto.frost_signer import (
    _hash_to_scalar, _lagrange_coefficient,
    NonceCommitment, SigningShare, FROSTSignature,
    FROSTParticipant, frost_coordinate
)
from src.crypto.bls_aggregate import (
    BLSPartialSignature, BLSAggregateSignature,
    BLSThresholdSigner, bls_aggregate_threshold, bls_verify_pairing
)
from src.crypto.batch_verifier import (
    CredentialToken, verify_token_batch_simd
)
from src.crypto.slasher import (
    SlashingProof, ByzantineSlasher
)
from src.epoch_manager import (
    EpochAdvanceRequest, EpochCertificate, EpochManager
)


# ==============================================================================
# DKG Unit & Branch Coverage
# ==============================================================================

def test_dkg_helpers_and_scalars():
    s = _random_scalar()
    assert 1 <= s < L
    b = _scalar_to_bytes(s)
    assert len(b) == 32
    s2 = _bytes_to_scalar(b)
    assert s2 == s

    pt = _scalar_mul_base(s)
    assert len(pt) == 32


def test_dkg_node_methods_and_branches():
    node = DKGNode(1, 2, 3)
    cmt = node.round1_generate()
    assert len(cmt.coefficients) == 2
    assert cmt.node_id == 1

    val = node.evaluate_poly(2)
    assert isinstance(val, int)

    sh = node.round2_share(2)
    assert sh.from_node == 1
    assert sh.to_node == 2

    # verify_share without receiving
    assert not node.verify_share(2, cmt)

    # receive share and verify
    node.receive_share(sh)
    assert node.verify_share(1, cmt)

    # finalize secret with self and other
    node.received_shares[2] = 12345
    sec = node.finalize_secret({1, 2})
    assert sec == node.secret_share


def test_dkg_complaints_and_disqualifications():
    transcript = DKGTranscript(
        t=2, n=3,
        commitments={
            1: Commitment(1, [b"\x01" * 32, b"\x02" * 32]),
            2: Commitment(2, [b"\x03" * 32, b"\x04" * 32]),
            3: Commitment(3, [b"\x05" * 32, b"\x06" * 32]),
        },
        shares={
            (1, 2): Share(1, 2, 100),
            (2, 1): Share(2, 1, 200),
        }
    )

    # Complaint with missing share
    transcript.complaints.append(Complaint(accuser=1, accused=3, reason="missing"))
    process_complaints(transcript, [])
    assert 3 in transcript.disqualified

    # Complaint with malformed share
    transcript.complaints.append(Complaint(accuser=1, accused=2, reason="malformed share"))
    process_complaints(transcript, [])
    assert 2 in transcript.disqualified

    # Complaint with revelation request (covers line 120)
    transcript.complaints.append(Complaint(accuser=2, accused=1, reason="revelation request"))
    process_complaints(transcript, [])
    assert (1, 2) in transcript.revealed

    # Finalize QUAL when qualified < t
    transcript.disqualified.add(1)
    with pytest.raises(RuntimeError):
        finalize_qual(transcript)


def test_run_dkg_full():
    tr = run_dkg(2, 3)
    assert tr.group_public_key is not None
    assert len(tr.qual) == 3
    assert len(tr.verification_shares) == 3


# ==============================================================================
# FROST Unit & Branch Coverage
# ==============================================================================

def test_frost_helpers_and_lagrange():
    h = _hash_to_scalar(b"test", b"scalar")
    assert 0 <= h < L

    # Lagrange for single signer
    lam = _lagrange_coefficient(1, {1})
    assert lam == 1

    # Lagrange for multiple signers
    lam2 = _lagrange_coefficient(1, {1, 2, 3})
    assert 0 <= lam2 < L


def test_frost_participant_and_signature():
    p = FROSTParticipant(1, 54321, b"\xaa" * 32)
    nonce = p.round1_nonce()
    assert nonce.node_id == 1
    assert len(nonce.D) == 32
    assert len(nonce.E) == 32

    sh = p.round2_sign(b"msg", {1: nonce}, {1}, b"\xbb" * 32)
    assert sh.node_id == 1
    assert isinstance(sh.z, int)

    sig = FROSTSignature(b"\x11" * 32, b"\x22" * 32)
    assert len(sig.to_bytes()) == 64


def test_frost_coordinate_full():
    tr = run_dkg(2, 3)
    parts = [
        FROSTParticipant(1, 100, tr.verification_shares[1]),
        FROSTParticipant(2, 200, tr.verification_shares[2]),
    ]
    sig = frost_coordinate(parts, b"hello", tr.group_public_key, 2)
    assert len(sig.to_bytes()) == 64


# ==============================================================================
# BLS Aggregate Coverage
# ==============================================================================

def test_bls_aggregate_all_paths():
    signer = BLSThresholdSigner(1, 42, b"\x01" * 32)
    p1 = signer.sign_partial(b"msg1")
    assert p1.node_id == 1
    assert len(p1.sig_point) == 32

    signer2 = BLSThresholdSigner(2, 84, b"\x01" * 32)
    p2 = signer2.sign_partial(b"msg1")

    agg = bls_aggregate_threshold([p1, p2], 2)
    assert agg.signers == {1, 2}
    assert bls_verify_pairing(agg, b"msg1", b"\x01" * 32)

    # Invalid point length check
    agg_bad = BLSAggregateSignature(b"\x00" * 16, {1, 2})
    assert not bls_verify_pairing(agg_bad, b"msg1", b"\x01" * 32)


# ==============================================================================
# Batch Verifier Coverage
# ==============================================================================

def test_batch_verifier_edge_cases():
    # Empty tokens
    valid, lat, bad = verify_token_batch_simd([])
    assert valid and lat == 0.0 and bad == []

    # Valid tokens
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signature = private_key.sign(b"m1")
    toks = [CredentialToken("t1", b"m1", signature, public_key)]
    valid, lat, bad = verify_token_batch_simd(toks)
    assert valid and bad == []

    toks_invalid = [CredentialToken("t1", b"m1", b"\x01" * 64, public_key)]
    valid, _, bad = verify_token_batch_simd(toks_invalid)
    assert not valid and bad == [0]

    # Corrupt signature length
    toks_bad_sig = [CredentialToken("t1", b"m1", b"\x01" * 32, b"\x02" * 32)]
    valid, lat, bad = verify_token_batch_simd(toks_bad_sig)
    assert not valid and 0 in bad

    # Corrupt public key length
    toks_bad_pk = [CredentialToken("t1", b"m1", b"\x01" * 64, b"\x02" * 16)]
    valid, lat, bad = verify_token_batch_simd(toks_bad_pk)
    assert not valid and 0 in bad


# ==============================================================================
# Slasher Coverage
# ==============================================================================

def test_slasher_all_branches():
    slasher = ByzantineSlasher()
    # Share 0
    assert not slasher.verify_partial_share(1, 0, b"", b"", b"", 0, 0, 0)
    # Share deadbeef
    assert not slasher.verify_partial_share(1, 0xdeadbeef, b"", b"", b"", 0, 0, 0)
    # Valid share
    assert slasher.verify_partial_share(1, 999, b"", b"", b"", 0, 0, 0)

    # Slash node
    proof = slasher.slash_node(1, "s1", b"m", 0, b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
    assert proof.rogue_node_id == 1
    assert 1 in slasher.slashed_nodes
    assert len(slasher.slashing_ledger) == 1

    # Dynamic rebalance when remaining >= target_t
    reb = slasher.dynamic_rebalance_quorum({1, 2, 3, 4}, {1, 2, 3, 4}, 1, 3)
    assert reb == {2, 3, 4}

    # Dynamic rebalance when replacement needed
    reb2 = slasher.dynamic_rebalance_quorum({1, 2, 3, 4}, {1, 2}, 1, 2)
    assert reb2 == {2, 3}

    # Dynamic rebalance when pool exhausted
    reb3 = slasher.dynamic_rebalance_quorum({1, 2}, {1, 2}, 1, 2)
    assert reb3 is None


# ==============================================================================
# Epoch Manager Coverage
# ==============================================================================

def test_epoch_manager_all_paths():
    tr = run_dkg(2, 3)
    mgr = EpochManager(tr, 2, db_path=":memory:")
    parts = [
        FROSTParticipant(1, 10, tr.verification_shares[1]),
        FROSTParticipant(2, 20, tr.verification_shares[2]),
    ]

    # Invalid advance jump (+2)
    req_bad = EpochAdvanceRequest("iss_1", 0, 2, b"\xaa" * 32)
    with pytest.raises(ValueError):
        mgr.request_advance(req_bad, parts)

    # Threshold signing is disabled until backed by real group operations.
    req_good = EpochAdvanceRequest("iss_1", 0, 1, b"\xaa" * 32)
    with pytest.raises(NotImplementedError):
        mgr.request_advance(req_good, parts)
    cert_bad_sig = EpochCertificate("iss_1", 1, b"\xaa" * 32, FROSTSignature(b"\x00" * 16, b"\x00" * 16), {1}, 0)
    assert not mgr.verify_certificate(cert_bad_sig)
