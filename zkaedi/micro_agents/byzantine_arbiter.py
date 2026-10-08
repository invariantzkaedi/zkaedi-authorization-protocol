"""
ZKAEDI Byzantine Arbiter — Multi-Agent Consensus & Rogue Agent Slasher
Detects conflicting, fabricated, or hallucinated subagent outputs and derives quorum consensus.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Any, Optional
import hashlib

@dataclass
class AgentProposal:
    agent_id: str
    action_type: str
    output_digest: str
    raw_payload: str

class ByzantineArbiter:
    def __init__(self, quorum_threshold: float = 0.67):
        self.quorum_threshold = quorum_threshold
        self.quarantined_agents: Set[str] = set()

    def arbitrate(
        self,
        proposals: List[AgentProposal]
    ) -> Tuple[Optional[str], List[str]]:
        """
        Derives consensus output digest and identifies rogue/dissenting agents.
        Returns (consensus_digest, slashed_agent_ids).
        """
        if not proposals:
            return None, []

        valid_proposals = [p for p in proposals if p.agent_id not in self.quarantined_agents]
        if not valid_proposals:
            return None, []

        counts: Dict[str, int] = {}
        for p in valid_proposals:
            counts[p.output_digest] = counts.get(p.output_digest, 0) + 1

        total = len(valid_proposals)
        best_digest = max(counts, key=counts.get)
        best_ratio = counts[best_digest] / total

        if best_ratio < self.quorum_threshold:
            # Quorum not reached
            return None, []

        # Identify rogue agents whose output did not match consensus
        slashed = []
        for p in valid_proposals:
            if p.output_digest != best_digest:
                slashed.append(p.agent_id)
                self.quarantined_agents.add(p.agent_id)

        return best_digest, slashed
