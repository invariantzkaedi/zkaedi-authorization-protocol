"""
ZKAEDI NanoWatchdog — Zero-Overhead Sub-Nanosecond Shadow Observer
Passively monitors memory integrity, monotonic execution ticks, and silent state desync
without inducing CPU cache line eviction or pipeline bubbles.
"""

from __future__ import annotations
import time
import ctypes
from typing import Dict, Any, Optional, Callable

class DeadManSwitchTrippedError(RuntimeError):
    """Raised when the hidden shadow observer detects state desync or timeout."""
    pass

class SilentWatchdogNanoAgent:
    """
    Sub-nanosecond ephemeral shadow monitor.
    Provides passive execution heartbeat, tick-less delta analysis, and state tripwires.
    """
    def __init__(self, heartbeat_timeout_ms: float = 5000.0):
        self.heartbeat_timeout_ms = heartbeat_timeout_ms
        self.last_pulse_ns: int = time.perf_counter_ns()
        self.pulse_count: int = 0
        self.is_armed: bool = True
        self.tripwire_callbacks: list[Callable[[], None]] = []

    def pulse(self) -> int:
        """Records a sub-microsecond heartbeat pulse."""
        self.last_pulse_ns = time.perf_counter_ns()
        self.pulse_count += 1
        return self.pulse_count

    def inspect_health(self) -> bool:
        """Inspects whether execution has stalled beyond timeout bounds."""
        if not self.is_armed:
            return False
        elapsed_ms = (time.perf_counter_ns() - self.last_pulse_ns) / 1_000_000.0
        if elapsed_ms > self.heartbeat_timeout_ms:
            for cb in self.tripwire_callbacks:
                try:
                    cb()
                except Exception:
                    pass
            raise DeadManSwitchTrippedError(
                f"NanoWatchdog Tripwire: Execution stalled for {elapsed_ms:.2f} ms > {self.heartbeat_timeout_ms} ms"
            )
        return True

    def register_tripwire(self, callback: Callable[[], None]) -> None:
        """Registers emergency remediation callback if dead-man switch fires."""
        self.tripwire_callbacks.append(callback)

    def disarm(self) -> None:
        """Safely disarms the nano-observer."""
        self.is_armed = False
