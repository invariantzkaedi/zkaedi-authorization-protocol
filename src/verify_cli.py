from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def load_trusted_keys(target: str) -> dict[bytes, bytes] | set[bytes]:
    """Loads trusted public keys from a file path (JSON or line-delimited hex) or a raw hex string."""
    path = Path(target)
    if path.exists() and path.is_file():
        content = path.read_text(encoding="utf-8").strip()
    else:
        content = target.strip()

    def _decode_key(val: str) -> bytes:
        val = val.strip()
        if len(val) == 44 and val.endswith("="):
            return base64.b64decode(val)
        return bytes.fromhex(val)

    # Try JSON
    if content.startswith("{") or content.startswith("["):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                return {_decode_key(k): _decode_key(v) for k, v in parsed.items()}
            elif isinstance(parsed, list):
                return {_decode_key(v) for v in parsed}
        except (ValueError, json.JSONDecodeError):
            pass

    # Try line-delimited text
    keys_dict: dict[bytes, bytes] = {}
    keys_set: set[bytes] = set()
    has_mapping = False

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key_id_str, pub_str = line.split(":", 1)
            keys_dict[_decode_key(key_id_str)] = _decode_key(pub_str)
            has_mapping = True
        else:
            keys_set.add(_decode_key(line))

    if has_mapping:
        return keys_dict
    if keys_set:
        return keys_set
    raise ValueError(f"Could not parse any valid trusted keys from {target}")


def verify_database(
    path: str,
    audit_key_or_checkpoint: bytes | str | None = None,
    checkpoint: str | None = None,
    *,
    audit_key: bytes | None = None,
    trusted_keys: dict[bytes, bytes] | set[bytes] | None = None,
) -> tuple[bool, int, int, str]:
    if isinstance(audit_key_or_checkpoint, bytes):
        audit_key = audit_key_or_checkpoint
    elif isinstance(audit_key_or_checkpoint, str):
        if checkpoint is None:
            checkpoint = audit_key_or_checkpoint

    if audit_key is not None and (not isinstance(audit_key, bytes) or len(audit_key) < 32):
        raise ValueError("audit_key must contain at least 32 bytes")

    uri = Path(path).resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        rows = connection.execute(
            "SELECT sequence, previous_hash, event_hash, payload FROM audit_events ORDER BY sequence"
        ).fetchall()
        keys = {
            key_id: public_key
            for key_id, public_key in connection.execute(
                "SELECT key_id, public_key FROM key_records WHERE purpose = 'receipt_signing'"
            )
        }
        receipt_rows = {
            sequence: (key_id, signature, signed_payload)
            for sequence, key_id, signature, signed_payload in connection.execute(
                "SELECT sequence, key_id, signature, signed_payload FROM zkaedi_receipts"
            )
        } if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkaedi_receipts'"
        ).fetchone() else {}
    except sqlite3.Error:
        connection.close()
        return False, 0, 0, "database schema could not be read"
    finally:
        try:
            connection.close()
        except sqlite3.Error:
            pass

    previous = b"\x00" * 32
    receipt_count = 0
    for expected_sequence, row in enumerate(rows, start=1):
        sequence, stored_previous, event_hash, payload = row
        if sequence != expected_sequence or not hmac.compare_digest(stored_previous, previous):
            return False, expected_sequence - 1, receipt_count, "audit sequence or previous hash mismatch"
        calculated_sha = hashlib.sha256(stored_previous + payload).digest()
        if hmac.compare_digest(event_hash, calculated_sha):
            pass
        elif audit_key is not None and hmac.compare_digest(
            event_hash, hmac.digest(audit_key, stored_previous + payload, hashlib.sha256)
        ):
            pass
        else:
            return False, expected_sequence, receipt_count, "audit event hash mismatch"
        try:
            event = json.loads(payload)
        except (TypeError, json.JSONDecodeError):
            return False, expected_sequence, receipt_count, "audit payload is not valid JSON"
        if isinstance(event, dict) and "service" in event:
            receipt = receipt_rows.get(sequence)
            if receipt is None:
                return False, expected_sequence, receipt_count, "signed audit event has no receipt"
            key_id, signature, signed_payload = receipt
            public_key = keys.get(key_id)
            if public_key is None:
                return False, expected_sequence, receipt_count, "receipt signing key is not registered"
            if trusted_keys is not None:
                if isinstance(trusted_keys, dict):
                    expected_pub = trusted_keys.get(key_id)
                    if expected_pub is None:
                        return False, expected_sequence, receipt_count, "receipt signing key is not in trusted keys"
                    if not hmac.compare_digest(public_key, expected_pub):
                        return False, expected_sequence, receipt_count, "receipt signing key does not match trusted public key"
                elif isinstance(trusted_keys, (set, list, tuple)):
                    if public_key not in trusted_keys:
                        return False, expected_sequence, receipt_count, "receipt signing key is not in trusted keys"
            try:
                signed = json.loads(signed_payload)
                if (
                    signed.get("sequence") != sequence
                    or signed.get("entry_hash") != event_hash.hex()
                    or signed.get("context_digest") != event.get("context_digest")
                    or signed.get("response_digest") != event.get("response_digest")
                    or signed.get("status") != event.get("status")
                    or signed.get("service") != event.get("service")
                    or event.get("key_id") != key_id.hex()
                ):
                    return False, expected_sequence, receipt_count, "receipt does not match audit event"
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed_payload)
            except (InvalidSignature, ValueError, TypeError, json.JSONDecodeError):
                return False, expected_sequence, receipt_count, "Ed25519 receipt signature is invalid"
            receipt_count += 1
        previous = event_hash

    if checkpoint is not None:
        if len(checkpoint) != 64:
            return False, len(rows), receipt_count, "checkpoint must be a 32-byte hex hash"
        try:
            expected_hash = bytes.fromhex(checkpoint)
        except ValueError:
            return False, len(rows), receipt_count, "checkpoint must be a 32-byte hex hash"
        if not hmac.compare_digest(previous, expected_hash):
            return False, len(rows), receipt_count, "checkpoint does not match chain head"
    return True, len(rows), receipt_count, previous.hex()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify ZKAEDI audit chain and Ed25519 receipts offline.")
    parser.add_argument("sqlite_path", help="Path to SQLite audit vault database")
    parser.add_argument("--checkpoint", help="Expected chain-head hash as 64 hexadecimal characters")
    parser.add_argument("--trusted-keys", help="Path to file or hex string containing pinned trusted public keys")
    parser.add_argument("--audit-key", help="(Optional) Legacy HMAC audit key if verifying a legacy keyed chain")
    args = parser.parse_args(argv)

    audit_key = None
    if args.audit_key:
        try:
            audit_key = bytes.fromhex(args.audit_key)
            if len(audit_key) < 32:
                raise ValueError("audit_key must contain at least 32 bytes")
        except ValueError as exc:
            print(f"FAIL: invalid --audit-key: {exc}")
            return 1
    elif "ZKAEDI_AUDIT_KEY" in os.environ and os.environ["ZKAEDI_AUDIT_KEY"]:
        try:
            audit_key = bytes.fromhex(os.environ["ZKAEDI_AUDIT_KEY"])
            if len(audit_key) < 32:
                raise ValueError("ZKAEDI_AUDIT_KEY must contain at least 32 bytes")
        except ValueError as exc:
            print(f"FAIL: invalid ZKAEDI_AUDIT_KEY: {exc}")
            return 1

    trusted_keys = None
    if args.trusted_keys:
        try:
            trusted_keys = load_trusted_keys(args.trusted_keys)
        except Exception as exc:
            print(f"FAIL: invalid --trusted-keys: {exc}")
            return 1

    if not args.trusted_keys and not args.checkpoint:
        print(
            "NOTICE: Verifying against embedded key_records without --trusted-keys or --checkpoint "
            "proves internal consistency, not authenticity against a rogue DBA with key-generation access."
        )

    try:
        valid, events, receipts, detail = verify_database(
            args.sqlite_path,
            checkpoint=args.checkpoint,
            audit_key=audit_key,
            trusted_keys=trusted_keys,
        )
    except (OSError, ValueError) as exc:
        valid, events, receipts, detail = False, 0, 0, str(exc)
    if valid:
        print(f"PASS: {events} audit events and {receipts} Ed25519 receipts verified")
        print(f"Chain head: {detail}")
        return 0
    print(f"FAIL: {events} audit events and {receipts} Ed25519 receipts verified; {detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
