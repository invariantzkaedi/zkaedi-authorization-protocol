"""
ZKAEDI Ghost Sanitizer — Secret Zeroization & Ephemeral Artifact Quarantine
Ensures memory structures, bytearrays, and temporary scratch disk files are securely wiped.
"""

from __future__ import annotations
import os
import ctypes
import shutil
from pathlib import Path
from typing import List, Optional

class GhostSanitizer:
    @staticmethod
    def zeroize_buffer(buf: bytearray) -> None:
        """Securely zeroes in-place bytearrays preventing heap retention."""
        if not isinstance(buf, bytearray):
            return
        for i in range(len(buf)):
            buf[i] = 0

    @staticmethod
    def secure_wipe_file(file_path: str | Path, passes: int = 1) -> bool:
        """Overwrites file contents with zeros before unlinking."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return False
        try:
            length = p.stat().st_size
            with open(p, "wb") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(b"\x00" * length)
                    f.flush()
                    os.fsync(f.fileno())
            p.unlink()
            return True
        except Exception:
            return False

    @staticmethod
    def sweep_temp_orphans(directory: str | Path, pattern: str = "*.tmp") -> int:
        """Sweeps and securely wipes stale temporary artifacts."""
        p = Path(directory)
        if not p.exists():
            return 0
        cleaned = 0
        for item in p.glob(pattern):
            if item.is_file():
                if GhostSanitizer.secure_wipe_file(item):
                    cleaned += 1
        return cleaned
