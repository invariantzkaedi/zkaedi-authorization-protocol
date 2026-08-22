"""
ZKAEDI Aegis Sentinel — Subagent Execution Sandboxing & Privilege Boundary Guard
Enforces strict path confinement, command whitelisting, and environment sanitization.
"""

from __future__ import annotations
import os
import re
from pathlib import Path
from typing import List, Set, Optional

class SecurityViolationError(PermissionError):
    """Raised when an unauthenticated or boundary-escaping action is attempted."""
    pass

class AegisSentinel:
    def __init__(self, allowed_roots: Optional[List[Path]] = None):
        self.allowed_roots = [r.resolve() for r in (allowed_roots or [Path.cwd()])]
        self.blocked_patterns = [
            re.compile(r"(rm\s+-rf\s+/|del\s+/s\s+/q|format\s+[A-Z]:)", re.I),
            re.compile(r"(nc\s+-e|bash\s+-i|curl\s+[^|]*\|\s*(?:ba)?sh)", re.I),
        ]
        self.audit_trail: List[str] = []

    def validate_path(self, target_path: str | Path) -> Path:
        """Validates that target_path does not escape allowed root boundaries."""
        resolved = Path(target_path).resolve()
        for root in self.allowed_roots:
            try:
                resolved.relative_to(root)
                self.audit_trail.append(f"PATH_ALLOW: {resolved}")
                return resolved
            except ValueError:
                continue
        err = f"Aegis Sentinel Boundary Trap: {resolved} is outside allowed roots {[str(r) for r in self.allowed_roots]}"
        self.audit_trail.append(f"PATH_DENY: {err}")
        raise SecurityViolationError(err)

    def validate_command(self, cmd_line: str) -> bool:
        """Validates shell command strings against destructive/exfiltration patterns."""
        for pattern in self.blocked_patterns:
            if pattern.search(cmd_line):
                err = f"Aegis Sentinel Command Trap: Hazardous pattern '{pattern.pattern}' detected in '{cmd_line}'"
                self.audit_trail.append(f"CMD_DENY: {err}")
                raise SecurityViolationError(err)
        self.audit_trail.append(f"CMD_ALLOW: {cmd_line[:64]}")
        return True

    def sanitize_env(self, env: dict[str, str]) -> dict[str, str]:
        """Strips toxic environmental variables from subprocess execution contexts."""
        dangerous_keys = {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "NODE_OPTIONS"}
        return {k: v for k, v in env.items() if k not in dangerous_keys}
