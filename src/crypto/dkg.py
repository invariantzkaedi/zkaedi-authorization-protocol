"""
Experimental DKG data-flow prototype; not a cryptographic DKG implementation.
Produces group public key Q and per-node secret shares s_i with QUAL set.
Do not use generated commitments or shares for security decisions.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
import hashlib
import secrets

# Ed25519 Prime Field Order ℓ
L = 2**252 + 27742317777372353535851937790883648493

def _random_scalar() -> int:
    return secrets.randbelow(L - 1) + 1

def _scalar_to_bytes(s: int) -> bytes:
    return (s % L).to_bytes(32, "little")

def _bytes_to_scalar(b: bytes) -> int:
    return int.from_bytes(b, "little") % L

def _scalar_mul_base(s_int: int) -> bytes:
    # Deterministic public commitment representation
    h = hashlib.sha256(b"ED25519_BASEPOINT_MULT" + _scalar_to_bytes(s_int)).digest()
    return h

@dataclass
class Commitment:
    node_id: int
    coefficients: List[bytes]          # C_ik = a_ik * B  (32-byte points)

@dataclass
class Share:
    from_node: int
    to_node: int
    value: int                         # s_ij  (scalar mod ℓ)

@dataclass
class Complaint:
    accuser: int
    accused: int
    share_claim: Optional[int] = None
    reason: str = "VSS verification failed"

@dataclass
class DKGTranscript:
    t: int
    n: int
    commitments: Dict[int, Commitment]
    shares: Dict[Tuple[int, int], Share]   # (from, to) → Share
    complaints: List[Complaint] = field(default_factory=list)
    revealed: Dict[Tuple[int, int], int] = field(default_factory=dict)
    qual: Set[int] = field(default_factory=set)
    disqualified: Set[int] = field(default_factory=set)
    group_public_key: Optional[bytes] = None
    verification_shares: Dict[int, bytes] = field(default_factory=dict)  # Y_i

class DKGNode:
    def __init__(self, node_id: int, t: int, n: int):
        assert 1 <= node_id <= n
        assert 1 <= t <= n
        self.id = node_id
        self.t = t
        self.n = n
        self.poly: List[int] = []            # a_i0 ... a_i,{t-1}
        self.commitments: List[bytes] = []   # C_ik
        self.received_shares: Dict[int, int] = {}
        self.secret_share: Optional[int] = None

    def round1_generate(self) -> Commitment:
        """Sample polynomial and publish public commitments."""
        self.poly = [_random_scalar() for _ in range(self.t)]
        self.commitments = [_scalar_mul_base(a) for a in self.poly]
        return Commitment(node_id=self.id, coefficients=self.commitments)

    def evaluate_poly(self, x: int) -> int:
        """Evaluate f_i(x) mod ℓ using Horner's method."""
        result = 0
        for a in reversed(self.poly):
            result = (result * x + a) % L
        return result

    def round2_share(self, to_node: int) -> Share:
        s = self.evaluate_poly(to_node)
        return Share(from_node=self.id, to_node=to_node, value=s)

    def receive_share(self, share: Share):
        self.received_shares[share.from_node] = share.value

    def verify_share(self, from_node: int, commitments: Commitment) -> bool:
        """Fails closed because this prototype does not implement VSS verification."""
        return False

    def finalize_secret(self, qual: Set[int]) -> int:
        """s_i = Σ_{j ∈ QUAL} f_j(i) mod ℓ"""
        total = 0
        for j in qual:
            if j in self.received_shares:
                total = (total + self.received_shares[j]) % L
            elif j == self.id:
                total = (total + self.evaluate_poly(self.id)) % L
        self.secret_share = total
        return total

def process_complaints(transcript: DKGTranscript, nodes: List[DKGNode]) -> None:
    """Processes complaints and updates disqualified nodes."""
    for c in transcript.complaints:
        key = (c.accused, c.accuser)
        original = transcript.shares.get((c.accused, c.accuser))
        if original is None or c.reason == "malformed share":
            transcript.disqualified.add(c.accused)
            continue
        transcript.revealed[key] = original.value

def finalize_qual(transcript: DKGTranscript) -> None:
    all_nodes = set(transcript.commitments.keys())
    transcript.qual = all_nodes - transcript.disqualified
    if len(transcript.qual) < transcript.t:
        raise RuntimeError(f"DKG aborted: {len(transcript.qual)} qualified nodes < threshold {transcript.t}")

    # Compute Group Public Key Q = Hash-Sum of C_i0 for i in QUAL
    hasher = hashlib.sha256(b"GROUP_PUBLIC_KEY")
    for i in sorted(transcript.qual):
        hasher.update(transcript.commitments[i].coefficients[0])
    transcript.group_public_key = hasher.digest()

def run_dkg(t: int, n: int) -> DKGTranscript:
    """Executes a complete dealerless DKG ceremony among n nodes with threshold t."""
    nodes = [DKGNode(i, t, n) for i in range(1, n + 1)]
    transcript = DKGTranscript(t=t, n=n, commitments={}, shares={})

    # Round 1: Commitments
    for node in nodes:
        c = node.round1_generate()
        transcript.commitments[node.id] = c

    # Round 2: Shares
    for i in nodes:
        for j in nodes:
            if i.id != j.id:
                sh = i.round2_share(j.id)
                transcript.shares[(i.id, j.id)] = sh
                j.receive_share(sh)

    # Finalize QUAL
    finalize_qual(transcript)

    # Final secret shares & verification shares Y_i
    for node in nodes:
        if node.id in transcript.qual:
            s = node.finalize_secret(transcript.qual)
            transcript.verification_shares[node.id] = _scalar_mul_base(s)

    return transcript
