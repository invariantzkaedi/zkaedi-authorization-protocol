from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_database(path: str, audit_key: bytes, checkpoint: str | None = None) -> tuple[bool, int, int, str]:
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
        calculated = hmac.digest(audit_key, stored_previous + payload, hashlib.sha256)
        if not hmac.compare_digest(event_hash, calculated):
            return False, expected_sequence, receipt_count, "audit event HMAC mismatch"
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
    parser.add_argument("sqlite_path")
    parser.add_argument("--checkpoint", help="Expected chain-head hash as 64 hexadecimal characters")
    args = parser.parse_args(argv)
    configured_key = os.environ.get("ZKAEDI_AUDIT_KEY")
    try:
        if configured_key is None:
            raise ValueError("ZKAEDI_AUDIT_KEY is not set")
        audit_key = bytes.fromhex(configured_key)
        if len(audit_key) < 32:
            raise ValueError("ZKAEDI_AUDIT_KEY must contain at least 32 bytes")
        valid, events, receipts, detail = verify_database(args.sqlite_path, audit_key, args.checkpoint)
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
