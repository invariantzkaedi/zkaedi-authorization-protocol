# ZKAEDI protocol specification (outline)

## Scope

This document outlines the existing credential protocol and the `@audited` action-receipt API. It is an implementation guide, not a substitute for reviewing the code and test vectors.

## Credential token wire format

The fixed-size credential envelope, field offsets, sizes, and interpretation are documented in the [README token wire format table](../README.md#-249-byte-token-wire-format-specification). It includes a protocol version, key identifier, packed epoch state, time bounds, issuer/principal/context/policy digests, and an Ed25519 signature. The current source constants and codec are authoritative for exact encoding and validation.

## Canonical audited context

The audited API canonicalizes a JSON object containing `principal_id`, `action`, the configured resource argument's value, and the parsed request body with `canonical_json_object`. Its SHA-256 digest binds the request context. Response bytes are separately SHA-256 hashed.

## Audit hash chain

An `audit_events` row contains a monotonically assigned sequence, the previous 32-byte hash, the current 32-byte hash, and canonical JSON payload bytes. Genesis is 32 zero bytes; for each event the implementation computes:

```text
event_hash = HMAC-SHA256(audit_key, previous_hash || payload)
```

Updates and deletions are blocked by SQLite triggers, but a database owner can remove triggers or alter the database file. Consumers should retain checkpoints outside the database and verify exports independently.

## Action receipt

An audit event is signed by an active Ed25519 key registered with purpose `receipt_signing`. The signed canonical JSON includes service, sequence, chain-entry hash, context digest, response digest, and status. The signature, signing key ID, and signed payload are stored separately in `zkaedi_receipts` to avoid making the chain hash circular. HTTP success responses carry base64 signature, sequence, event hash, and key ID headers.

## Key lifecycle and verifier

Receipt private seeds are encrypted with AES-GCM using a key derived from the configured audit key and service name; encrypted seeds and key metadata are stored in SQLite. Protect and rotate the audit key as a secret. The verifier reads the audit key from `ZKAEDI_AUDIT_KEY`, recomputes HMACs, and verifies every registered receipt signature. An optional checkpoint compares the supplied chain-head hash with the verified final hash.

## Idempotency

An `Idempotency-Key` is reserved before handler execution and associated with the context digest. Matching committed keys replay the stored response and original receipt headers. A conflicting context or an in-progress key returns HTTP 409.
