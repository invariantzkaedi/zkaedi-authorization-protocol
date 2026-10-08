# ZKAEDI Protocol Specification

## 1. Scope & System Overview

This specification details the wire formats, cryptographic constructions, hash chaining rules, receipt mechanisms, and key lifecycle management in the ZKAEDI framework.

---

## 2. Canonical Audited Context

When a request enters an `@audited` endpoint:
1. **Context Construction**: The middleware extracts:
   - `principal_id`: Resolved via `principal_resolver(request)` (defaults to `X-Principal-Id` header or `"anonymous"`).
   - `action`: Explicit action string passed to `@audited(action="...")`.
   - `resource`: Parameter name resolved from request path/query/body.
   - `payload`: Normalized request body dictionary.
2. **Context Digest**: The canonical JSON representation (`canonical_json_object`) is computed, sorted by keys without whitespace delimiters, and digested:
   ```text
   context_digest = SHA-256(canonical_json(context))
   ```
3. **Response Digest**: Upon handler completion, response payload bytes are digested:
   ```text
   response_digest = SHA-256(response_bytes)
   ```

---

## 3. Public Audit Hash Chain

Audit events are stored in the `audit_events` SQLite table with `STRICT` typing:
```sql
CREATE TABLE audit_events(
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    previous_hash BLOB NOT NULL,
    event_hash BLOB NOT NULL,
    payload BLOB NOT NULL
) STRICT;
```

### Hash Chaining Formula
The hash chain is public and unkeyed:
- **Genesis Block**: Sequence 1 uses `previous_hash = 0x00 * 32` (32 zero bytes).
- **Subsequent Blocks**:
  ```text
  event_hash = SHA-256(previous_hash || canonical_payload)
  ```
Because the hash chain is unkeyed SHA-256, any external observer or auditor can verify the mathematical continuity of the entire log without possession of any shared secrets.

---

## 4. Ed25519 Action Receipts

To bind the event to a cryptographic identity and prevent unauthorized additions by non-service entities, each audit event is accompanied by an Ed25519 action receipt.

### Receipt Structure
The receipt signs the canonical JSON receipt payload:
```json
{
  "service": "billing-service",
  "sequence": 42,
  "entry_hash": "<64-hex-event_hash>",
  "context_digest": "<64-hex-context_digest>",
  "response_digest": "<64-hex-response_digest>",
  "status": 200
}
```
The Ed25519 signature is computed over `canonical_json(receipt_payload)`.

### Storage & Response Headers
The receipt is stored in `zkaedi_receipts`:
```sql
CREATE TABLE zkaedi_receipts(
    sequence INTEGER PRIMARY KEY,
    key_id BLOB NOT NULL,
    signature BLOB NOT NULL,
    signed_payload BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
```
Successful HTTP responses emit:
- `X-Zkaedi-Receipt-Signature`: Base64-encoded 64-byte Ed25519 signature.
- `X-Zkaedi-Sequence`: Decimal integer sequence number.
- `X-Zkaedi-Event-Hash`: Hex-encoded 32-byte event hash.
- `X-Zkaedi-Key-Id`: Hex-encoded 16-byte signing key ID.

---

## 5. Key Lifecycle & KEK Isolation

### Key-Encryption Key (KEK)
The Ed25519 private seed is encrypted at rest using AES-256-GCM. The encryption key is derived exclusively using HKDF/HMAC from the `ZKAEDI_KEY_ENCRYPTION_KEY`:
```text
KEK = HMAC-SHA256(ZKAEDI_KEY_ENCRYPTION_KEY, "zkaedi-receipt-private-key-v1\x00" || service_name)
```
- **Isolation Guarantee**: The KEK is never stored in the database and never transmitted to auditors or external verifiers.
- **Key Registration**: The public key is stored in `key_records` with purpose `receipt_signing` and state `ACTIVE`.

### Rotation States
Keys transition monotonically:
```text
ACTIVE -> VERIFY_ONLY -> RETIRED
```
Native SQLite trigger `key_records_status_guard` blocks illegal transitions.

---

## 6. Offline Zero-Secret Verifier & Checkpoints

The offline verification CLI (`src/verify_cli.py`) operates with **zero secrets**:
1. Connects to SQLite in read-only mode (`?mode=ro`).
2. Iterates rows in `audit_events` from `sequence = 1` upward.
3. Verifies `previous_hash == expected_previous` and `event_hash == SHA-256(previous_hash || payload)`.
4. Retrieves the registered public key from `key_records` for each receipt in `zkaedi_receipts` and validates the Ed25519 signature over `signed_payload`.
5. Validates that `signed_payload` matches the event fields and `entry_hash`.
6. (Optional) If `--trusted-keys <file>` is provided, validates that each signing key is pinned out-of-band, rejecting any rogue DBA key-replacement attacks.
7. (Optional) If `--checkpoint <hex>` is provided, verifies that the final chain head matches the trusted checkpoint.

---

## 7. External Checkpoint Anchoring

To protect against tail truncation or total database destruction:
- `AuditRecorder.export_checkpoint()` returns `{sequence, chain_head, receipt_signature, key_id, service, timestamp}`.
- `AuditRecorder.export_public_keys()` returns `{key_id_hex: public_key_hex}` for out-of-band key pinning.
- `ZkaediMiddleware(checkpoint_sink=...)` invokes an external callback on every committed mutation.
- Built-in concrete sinks:
  - `stdout_checkpoint_sink`: Streams single-line JSON records (`{"event": "zkaedi.checkpoint", ...}`) to standard output for log shippers (FluentBit, Vector, Datadog Agent).
  - `file_checkpoint_sink(path)`: Appends JSON lines to a mounted log volume or out-of-band file.
