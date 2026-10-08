# Threat Model & Security Architecture

## Assets and Security Goals

The assets protected by ZKAEDI include:
1. **Audit-event payloads and order**: Monotonically sequenced records of sensitive application operations.
2. **Ed25519 action receipts**: Cryptographic signatures binding the state mutation, sequence, context digest, and response digest to an authorized service signing identity.
3. **Registered public keys**: The append-only public key ledger (`key_records`) registering authorized receipt-signing public keys and lifecycle states.
4. **Response & idempotency records**: Cached responses and hashes preventing double-execution of non-idempotent operations.
5. **Key-encryption key (KEK)**: The isolated secret (`ZKAEDI_KEY_ENCRYPTION_KEY`) used strictly by the application server to encrypt/decrypt private Ed25519 signing seeds at rest.

The security goal is to make **any unauthorized modification, deletion, reordering, or insertion of audit events immediately and cryptographically detectable by an external verifier possessing zero secrets**.

---

## Secret Decoupling: Zero-Secret Verification Invariant

In traditional HMAC-based audit logs, the verification oracle shares a symmetric secret with the logger. This creates a fatal security flaw: **anyone who can verify can also forge**, and sharing the audit key with auditors or downstream collectors exposes the private key-encryption key if derived from the same source.

ZKAEDI resolves this by strictly decoupling signing secrets from verification:
- **Hash Chain**: Pure unkeyed `SHA-256(previous_hash || canonical_payload)`. Anyone with public read access can verify chain continuity.
- **Action Receipts**: Each event hash is signed with Ed25519 by the service. The verifier validates the signature using only the service's public key registered in `key_records`.
- **KEK Isolation**: `ZKAEDI_KEY_ENCRYPTION_KEY` is derived exclusively on the application server to protect the Ed25519 private seed via AES-256-GCM. It is never shared with auditors, verifiers, or external log consumers.
- **Offline CLI Verifier**: `python -m src.verify_cli <sqlite_path>` runs with **zero environment variables and zero secrets**.

---

## Attacker Models

### 1. Database Administrator (Untrusted Storage)

- **Capabilities**: Full access to the database file or SQLite server process. Can read, update, delete, reorder rows, or execute `DROP TRIGGER` to bypass SQL-level constraints.
- **Protections**:
  - **Payload Tampering**: Modifying any payload invalidates both the SHA-256 chain and the Ed25519 receipt signature.
  - **Reordering**: Changing row sequences or swapping rows breaks the `previous_hash` linkage.
  - **Row Insertion**: An attacker cannot generate valid Ed25519 signatures for inserted events without the private signing key.
  - **Tail Truncation**: Deleting recent rows from the end of the table is detectable by comparing against an externally retained checkpoint (`--checkpoint <64-hex-chain-head>`).
- **Defense-in-Depth vs Cryptographic Boundary**: SQLite triggers (`audit_events_update_guard`, `audit_events_delete_guard`, `key_records_delete_guard`) provide runtime defense-in-depth against application bugs or accidental SQL updates. They are **not** considered a cryptographic boundary against a malicious DBA with direct file access. Cryptographic proof is enforced exclusively via hash chains and Ed25519 signatures.

### 2. Auditor / Downstream Log Collector (Untrusted Verifier)

- **Capabilities**: Obtains a copy of the SQLite database or stream of audit events. May attempt to alter records to conceal non-compliance or frame an operator.
- **Protections**: The auditor receives **only public keys** and the SQLite database. Possessing zero secrets, the auditor has no ability to decrypt private signing seeds or forge historical receipts. Any offline verification failure produces a deterministic diagnostic identifying the exact sequence and type of tamper.

### 3. Compromised Application Server

- **Capabilities**: An attacker achieves code execution inside the application container, gaining access to `ZKAEDI_KEY_ENCRYPTION_KEY` and the active Ed25519 signing key.
- **Protections**:
  - The attacker can sign fraudulent *future* events from that point forward.
  - However, **past history cannot be rewritten** if external checkpoints have been published. Because `AuditRecorder.export_checkpoint()` and `ZkaediMiddleware(checkpoint_sink=...)` publish `(sequence, chain_head, receipt_signature)` to external sinks (e.g. Sentry, CloudWatch, syslog, immutable object storage), rewriting historical records produces an alternate chain head that contradicts already-witnessed external checkpoints.

### 4. Client Replay & Parameter Tampering

- **Capabilities**: A client replays a previously submitted mutation request with the same or modified body, or attempts to harvest responses.
- **Protections**:
  - If a client supplies an `Idempotency-Key` with an identical payload, ZKAEDI returns `IDEMPOTENT_REPLAY` with the original cached response and receipt headers without re-executing handler logic.
  - If a client attempts to reuse an `Idempotency-Key` with a altered payload or context, ZKAEDI detects the `context_digest` mismatch and immediately aborts with `HTTP 409 Conflict`.

---

## Assumptions and Operational Boundaries

1. **External Checkpoint Retention**: To protect against complete database deletion or tail truncation, operators must configure an external checkpoint sink (e.g., S3 Object Lock, external audit service, or log stream) receiving periodic checkpoints from `export_checkpoint()`.
2. **Decorator Coverage**: Only endpoints decorated with `@audited` generate audit events and receipts. Unadorned endpoints are executed without audit tracking.
3. **Response Model**: Payloads and responses must be JSON-serializable to produce canonical digests. Streaming response bodies are not currently supported.
4. **Key Rotation Hygiene**: Operators should retire and rotate receipt signing keys periodically. When a key is retired, it moves to `VERIFY_ONLY`, preserving verification of historical receipts while preventing new signatures.
