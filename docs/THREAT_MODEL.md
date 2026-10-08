# Threat model (outline)

## Assets and security goals

Assets include audit-event payloads and order, receipt signatures, registered public keys, response/idempotency records, the HMAC audit key, and encrypted Ed25519 private-key seeds. The goal is to make unauthorized edits detectable to a verifier that has a trusted audit key, public-key registry, and (where needed) an external checkpoint.

## Attacker models

### Database administrator

A database administrator may read, alter, reorder, or delete stored rows and may disable SQLite triggers. HMAC verification detects changes to surviving chain rows when the audit key is held separately. Ed25519 receipts make alteration of signed event fields detectable without trusting database contents, assuming signing private keys remain secret. Deleting a tail or the whole database requires a separately retained checkpoint or export to detect.

### Log-collector compromise

An attacker who controls a downstream collector may drop, reorder, or alter collected events. Verify event sequence and chain continuity against trusted checkpoints and compare exports from independent collection points. ZKAEDI does not secure the collector or guarantee delivery of events to it.

### Key compromise

Compromise of the audit key enables forged HMAC chains and decrypting stored private seeds protected by that key. Compromise of an Ed25519 private key enables forged receipts. Restrict access, rotate compromised keys, and retain public-key/status history and checkpoints outside the affected database. Past signatures do not prove that a signing key was uncompromised when used.

### Replay

Identical requests carrying an `Idempotency-Key` replay the saved response and receipt; a payload mismatch for the same key is rejected. This is scoped to the SQLite database and key value, and does not provide distributed replay prevention across independent databases or deployments.

## Assumptions and limitations

- The audit key and private signing key are protected from the database attacker; operators keep external checkpoints and public-key history.
- Middleware only records routes decorated with `@audited`; route coverage and event selection must be configured and reviewed by the application owner.
- Local SQLite durability and access controls are not a remote immutable storage service, a SIEM, or a compliance certification.
- Response serialization and request-body parsing follow the JSON request/response model; streaming response bodies are not a suitable target for this decorator.
