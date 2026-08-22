"""
ZKAEDI Invariant Oracle — Mathematical Integrity & Safety Sentinel
Validates mathematical boundaries, non-finite traps, hysteresis persistence, and row-stochasticity.
"""

from __future__ import annotations
import math
from typing import List, Dict, Any, Optional

class InvariantViolationError(ValueError):
    """Raised when a mathematical, numerical, or state transition invariant is breached."""
    pass

class InvariantOracle:
    def __init__(self, min_energy: float = -100.0, max_energy: float = 100.0):
        self.min_energy = min_energy
        self.max_energy = max_energy

    def assert_finite(self, name: str, value: float) -> float:
        """Traps NaN and +/-Inf floating point values."""
        if not math.isfinite(value):
            raise InvariantViolationError(f"Non-finite floating point trapped for '{name}': {value}")
        return value

    def assert_energy_bounds(self, energy: float) -> float:
        """Enforces canonical energy range [-100.0, 100.0]."""
        self.assert_finite("energy", energy)
        if not (self.min_energy <= energy <= self.max_energy):
            raise InvariantViolationError(f"Energy boundary violation: {energy} not in [{self.min_energy}, {self.max_energy}]")
        return energy

    def verify_row_stochastic(self, row: List[float], tol: float = 1e-6) -> bool:
        """Asserts sum of row elements equals 1.0."""
        for v in row:
            self.assert_finite("coupling_weight", v)
            if v < 0.0:
                raise InvariantViolationError(f"Negative coupling weight: {v}")
        s = sum(row)
        if abs(s - 1.0) > tol:
            raise InvariantViolationError(f"Row-stochastic invariant broken: sum={s} != 1.0 (tol={tol})")
        return True

    def verify_hysteresis_persistence(self, history: List[int], k: int = 3) -> bool:
        """Verifies that state transitions satisfy K-step persistence."""
        if len(history) < k:
            return True
        last_k = history[-k:]
        # If all k steps agree, transition is confirmed
        return len(set(last_k)) == 1
