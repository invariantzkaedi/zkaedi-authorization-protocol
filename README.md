# ZKAEDI — Cryptographic Action Receipts & Tamper-Evident Audit Trails

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![SQLite STRICT](https://img.shields.io/badge/SQLite-3.37%2B%20STRICT-green.svg)](https://www.sqlite.org/strictunpack.html)
[![Ed25519 Cryptography](https://img.shields.io/badge/security-Ed25519-red.svg)](https://cryptography.io/)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25%20(ZD--100)-brightgreen.svg)](tests/test_zd100_coverage.py)
[![Adversarial Fuzzing: 10,000 PASS](https://img.shields.io/badge/fuzzing-10%2C000%20mutations-success.svg)](tests/fuzz_adversarial_gauntlet.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Receipts for your backend. Every sensitive mutation signed with Ed25519, chained in an append-only hash log, and verifiable offline.

## Why ZKAEDI?

Anyone with database or log-collector access can silently alter ordinary audit logs. Auditors increasingly ask for evidence that records have not been changed after the fact. ZKAEDI adds independently verifiable proofs to application actions:

- **Ed25519 commit receipts** bind an action and its result to a registered signing key.
- **Append-only SHA-256 hash chain** detects modifications and breaks in event order.
- **Zero-secret offline verifier** checks the chain and receipt signatures with **zero secrets**—no shared keys or environment variables needed.
- **Replay idempotency** returns the original response and receipt for an identical request without double-executing.

## ⚡ Quickstart (60 seconds)

Install the existing dependencies with `pip install -r requirements.txt`, then set `ZKAEDI_KEY_ENCRYPTION_KEY` (a 32-byte hex key used to protect signing keys at rest):

```python
import os
from fastapi import FastAPI
from pydantic import BaseModel
from zkaedi import audited, ZkaediMiddleware, file_checkpoint_sink

class RefundRequest(BaseModel):
    amount_minor: int

app = FastAPI()
app.add_middleware(
    ZkaediMiddleware,
    service_name="billing-service",
    sqlite_path="/var/data/audit_vault.db",
    key_encryption_key=os.environ["ZKAEDI_KEY_ENCRYPTION_KEY"],
    checkpoint_sink=file_checkpoint_sink("/var/log/checkpoints.jsonl"),
)

@app.post("/api/v1/payouts/{account_id}/refund")
@audited(action="payout.refund", resource="account_id", severity="CRITICAL")
async def refund_customer(account_id: str, payload: RefundRequest):
    return {"status": "ok"}
```

Successful responses include a signed receipt and the associated chain position. Verify the persisted audit database offline with **zero secrets**:

```console
$ zkaedi-verify /var/data/audit_vault.db --trusted-keys pinned_keys.json
PASS: 1 audit events and 1 Ed25519 receipts verified
Chain head: fba87da299df996e8bde412e3d0bcbde78d4c4b4b695fdb4cdb06f1c80ffbf86
```

- Supply `--trusted-keys <path>` to pin authorized signing keys out-of-band, rejecting rogue DBA key-replacement attacks.
- Supply `--checkpoint <64-hex-chain-head>` to assert the chain matches an externally published checkpoint.
- Pass `checkpoint_sink=file_checkpoint_sink("/var/log/checkpoints.jsonl")` (or `stdout_checkpoint_sink`) to stream checkpoints off-host into log aggregators (Vector, FluentBit) on every committed mutation.

## What ZKAEDI is NOT

- **Not an authentication provider**: Keep Clerk, Auth0, or Cognito for user identity. ZKAEDI proves what happened *after* authentication.
- **Not a SIEM or log search engine**: It produces cryptographic proofs and action receipts; pipe your logs to Datadog, CloudWatch, or S3 as usual.
- **Single-node SQLite today**: Hardened on SQLite 3.37+ in `STRICT` mode; PostgreSQL support is on the active roadmap.

## Use cases

- SOC 2, HIPAA, and PCI audit trails for sensitive application mutations.
- Fintech action receipts for payouts, refunds, and ledger operations.
- AI-agent action logging where operators need a verifiable record of actions.

See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for a careful control mapping.

## Deep dive

A zero-trust, fail-closed authorization, credential issuance, and linearizable ledger transaction engine written in Python and backed by SQLite 3.37+ in `STRICT` mode.

---

## 🏛️ Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │          FastAPI REST Client           │
                      └───────────────────┬────────────────────┘
                                          │ HTTP REST API (HSTS / Security Headers)
                                          ▼
                      ┌────────────────────────────────────────┐
                      │    v26.0 Hardened API Microservice     │
                      │             (src/api_service.py)       │
                      └───────────────────┬────────────────────┘
                                          │
               ┌──────────────────────────┼──────────────────────────┐
               ▼                          ▼                          ▼
  ┌────────────────────────┐ ┌────────────────────────┐ ┌────────────────────────┐
  │  Token Issuance API    │ │   Transfer Engine      │ │ Key Lifecycle Manager  │
  │  (/api/v1/auth/issue)  │ │ (/api/v1/auth/transfer)│ │ (/api/v1/keyring/*)    │
  └────────────┬───────────┘ └────────────┬───────────┘ └────────────┬───────────┘
               │                          │                          │
               └──────────────────────────┼──────────────────────────┘
                                          ▼
                      ┌────────────────────────────────────────┐
                      │    Context-Bound Epoch Protocol        │
                      │  (src/context_bound_epoch_protocol.py) │
                      │   - Ed25519KeyRing                     │
                      │   - CredentialCodec                    │
                      │   - LinearizableEngine                 │
                      │   - SQLite STRICT & Native Triggers    │
                      └────────────────────────────────────────┘
```

---

## 🔥 Key Security Invariants

1. **Ed25519 Context-Bound Credentials:**
   Fixed 249-byte binary tokens signed with Ed25519 containing 64-bit packed epoch state, validity time windows, issuer digests, principal digests, and request HMACs.
2. **Linearizable Ledger & Replay Idempotency:**
   Executes transfers inside SQLite transactions and generates **Ed25519 commit receipts**. Replaying a token returns `IDEMPOTENT_REPLAY` with the verified receipt without double-executing.
3. **Persistent Key Registry & Native SQLite Triggers:**
   - `key_records_status_guard`: Native trigger preventing SQL-level reactivation of rotated/retired keys (`ACTIVE` $\rightarrow$ `VERIFY_ONLY` $\rightarrow$ `RETIRED`).
   - `key_records_delete_guard`: Native trigger blocking `DELETE FROM key_records`.
4. **Cross-Process Key Synchronization:**
   Signers and verifiers re-sync status with SQLite on every operation, immediately zeroizing in-memory private key material when rotated by a concurrent process.
5. **Append-Only Audit Hash Chain:**
   SHA-256 HMAC hash chain that detects head, middle, or tail deletions against trusted checkpoints.

---

## 📦 249-Byte Token Wire Format Specification

Tokens are compact, fixed-size binary structures encoded without variable-length delimiters to prevent parser-differential attacks:

| Field Name | Offset | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Magic Byte** | `0` | `1` | Fixed protocol version identifier (`0x40` for v26.0) |
| **Key ID** | `1` | `16` | Key identifier of the signing key pair |
| **Packed State** | `17` | `8` | 64-bit packed bitfield: `generation:16`, `identity:12`, `role:12`, `device:12`, `session:12` |
| **Issuer Epoch** | `25` | `8` | Big-endian uint64 global issuer epoch counter |
| **Not Before** | `33` | `8` | Unix epoch timestamp (seconds) before which the token is invalid |
| **Expires At** | `41` | `8` | Unix epoch timestamp (seconds) after which the token is expired |
| **Issuer Digest** | `49` | `32` | SHA-256 hash of the normalized issuer URI |
| **Principal Digest** | `81` | `32` | BLAKE2b keyed digest over `(principal_id, packed_state)` |
| **Context Digest** | `113` | `32` | SHA-256 hash over canonical `(resource, action, audience, request_payload)` |
| **Policy Digest** | `145` | `32` | SHA-256 hash of the canonical JSON policy rules |
| **Ed25519 Signature** | `177` | `64` | Cryptographic signature over payload bytes `0..176` |
| **Envelope Total** | — | **`241 bytes`** | *(Encapsulated in 249-byte structured wire frame)* |

---

## 🛡️ Complete Rejection & Authorization Status Matrix

The protocol returns strict, disambiguated `AuthStatus` enum integers on all verification paths:

| Enum Code | Name | Description |
| :--- | :--- | :--- |
| `0` | `COMMIT_SUCCESS` | Token verified, policy passed, and transfer committed to ledger |
| `1` | `IDEMPOTENT_REPLAY` | Identical valid token previously executed; returning original signed receipt |
| `2` | `REJECT_EXPIRED` | Token timestamp is strictly greater than `expires_at` |
| `3` | `REJECT_NOT_YET_VALID` | Token timestamp is strictly less than `not_before` |
| `4` | `REJECT_INVALID_SIGNATURE`| Ed25519 cryptographic signature check failed |
| `5` | `REJECT_STATE_MISMATCH` | Principal live epoch bitfield does not match token `packed_state` |
| `6` | `REJECT_ISSUER_EPOCH_MISMATCH`| Global issuer epoch counter does not match token `issuer_epoch` |
| `7` | `REJECT_POLICY_MISMATCH` | Live active policy SHA-256 digest differs from token `policy_digest` |
| `8` | `REJECT_UNKNOWN_PRINCIPAL`| Principal ID not found in live database registry |
| `9` | `REJECT_UNKNOWN_ISSUER` | Issuer URI digest not found in live database registry |
| `10` | `REJECT_UNKNOWN_POLICY` | Policy name not registered in live database |
| `11` | `REJECT_CREDENTIAL_CONFLICT`| Credential ID exists in ledger with conflicting token/principal payload |
| `12` | `REJECT_RESULT_TAMPERED` | Persisted receipt payload hash mismatch detected |
| `13` | `REJECT_INVALID_REQUEST` | Malformed request parameters or negative minor amount |
| `14` | `REJECT_INSUFFICIENT_FUNDS`| Source account balance is less than transfer amount |
| `15` | `REJECT_KEY_NOT_ACTIVE` | Signing key is not in `ACTIVE` state for new issuances |
| `16` | `REJECT_LEGACY_RESULT_UNVERIFIED`| Missing receipt signature in legacy unmigrated record |

---

## 🗄️ Database Schema & SQLite STRICT Tables

All state persistence uses native SQLite 3.37+ `STRICT` mode tables with append-only hash chains:

```sql
-- Principal Authority & Packed Epochs
CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    packed_state BLOB NOT NULL,
    version INTEGER NOT NULL
) STRICT;

-- Global Issuer Epochs
CREATE TABLE IF NOT EXISTS issuers (
    issuer_digest BLOB PRIMARY KEY,
    issuer_epoch BLOB NOT NULL
) STRICT;

-- Canonical Policies
CREATE TABLE IF NOT EXISTS policies (
    policy_name TEXT PRIMARY KEY,
    policy_digest BLOB NOT NULL
) STRICT;

-- Financial Ledger Accounts
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    balance_minor INTEGER NOT NULL CHECK(balance_minor >= 0),
    version INTEGER NOT NULL
) STRICT;

-- Persistent Key Registry
CREATE TABLE IF NOT EXISTS key_records (
    key_id BLOB PRIMARY KEY,
    public_key BLOB NOT NULL,
    status TEXT NOT NULL,
    purpose TEXT NOT NULL,
    issuer_digest BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Idempotent Credential Execution Receipts
CREATE TABLE IF NOT EXISTS credential_results (
    credential_id BLOB PRIMARY KEY,
    status INTEGER NOT NULL,
    token_digest BLOB NOT NULL,
    principal_digest BLOB NOT NULL,
    result_digest BLOB NOT NULL,
    result_payload BLOB NOT NULL,
    receipt_signature BLOB NOT NULL,
    receipt_key_id BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Cryptographic Audit HMAC Chain
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    event_hash BLOB NOT NULL,
    previous_hash BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    payload BLOB NOT NULL
) STRICT;
```

---

## 📊 Empirical Performance & Latency Benchmarks (Vector 2)

Measured under WSL2 / CPython 3.12:

### 1. Stateless Cryptographic Operations (5,000 Samples)
- **Token Issuance (Sign + Digests + Packing):** `24,000+ ops/sec` (Median: `0.036 ms` / 36 µs, p99: `0.099 ms`)
- **Token Verification (Verify + HMAC + Unpacking):** `12,500+ ops/sec` (Median: `0.071 ms` / 71 µs, p99: `0.153 ms`)

### 2. Multi-Worker Concurrent SQLite Contention
- **8 Workers Concurrent `BEGIN IMMEDIATE`:** `151.1 committed tx/sec` (Median commit latency: `6.609 ms`)
- **Audit Chain Integrity:** 100% byte-verified across all multi-threaded races with `0` corruption errors.

---

## 💻 Python SDK Usage Example

```python
import secrets
import time
from src.context_bound_epoch_protocol import (
    AuthorizationDatabase,
    CredentialCodec,
    Ed25519KeyRing,
    KeyPurpose,
    LinearizableEngine,
    pack_state,
    canonical_json_object,
)

# 1. Initialize Database & Keyrings
db = AuthorizationDatabase("ledger.db")
issuer = "https://auth.enterprise.net"
db.initialize_issuer(issuer, epoch=0)

cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, db)
receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, db)
cred_k_id = cred_keyring.generate(issuer)
receipt_k_id = receipt_keyring.generate(issuer)

binding_key = secrets.token_bytes(32)
audit_key = secrets.token_bytes(32)
codec = CredentialCodec(cred_keyring, binding_key, deployment_id="us-east-prod")
engine = LinearizableEngine(db, codec, audit_key, receipt_keyring, receipt_k_id)

# 2. Register Principal & Policy
p_state = pack_state(generation=1, identity=1, role=2, device=1, session=1)
db.initialize_principal("usr_100", p_state)
policy_digest = db.set_policy("transfer_policy", b'{"allow_transfer": true}')
db.create_account("vault_a", 10000)
db.create_account("vault_b", 5000)

# 3. Issue Token & Execute Transfer
now = int(time.time())
req_bytes = canonical_json_object({
    "action": "transfer",
    "amount_minor": 500,
    "source_account": "vault_a",
    "destination_account": "vault_b",
})

token = codec.issue(
    key_id=cred_k_id,
    packed_state=p_state,
    issuer_epoch=0,
    issued_at=now,
    not_before=now,
    expires_at=now + 300,
    issuer=issuer,
    principal_id="usr_100",
    audience="https://api.vault",
    resource="ledger",
    action="transfer",
    request_bytes=req_bytes,
    policy_digest=policy_digest,
)

result = engine.execute_transfer(
    token,
    current_time=now,
    expected_issuer=issuer,
    expected_principal_id="usr_100",
    expected_audience="https://api.vault",
    expected_resource="ledger",
    expected_action="transfer",
    expected_request_bytes=req_bytes,
    expected_policy_name="transfer_policy",
)

print(f"Status: {result.status.name} | Balance A: {db.get_balance('vault_a')} | Receipt Signature: {result.receipt_signature.hex()[:16]}...")
```

---

## 📁 Repository Layout

```text
zkaedi-authorization-protocol/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── docs/
│   ├── COMPLIANCE.md
│   ├── SPEC.md
│   └── THREAT_MODEL.md
├── src/
│   ├── __init__.py
│   ├── api_service.py                   # FastAPI REST Microservice
│   ├── audited.py                       # Audited decorator, middleware, recorder
│   ├── context_bound_epoch_protocol.py  # Core Protocol Engine (v26.0)
│   └── verify_cli.py                    # Offline audit and receipt verifier
└── tests/
    ├── test_audited.py                  # Action receipt and middleware integration tests
    ├── benchmark_concurrency_latency.py # Vector 2: Concurrency & Latency Benchmarks
    ├── fuzz_adversarial_gauntlet.py     # Vector 1: 10,000 Adversarial Mutations
    ├── test_api_service.py              # Microservice Route & Integration Suite
    ├── test_protocol.py                 # Core Engine Master Cumulative Suite
    └── test_zd100_coverage.py           # ZD-100 100% Statement Coverage Gauntlet
```

---

## Developing & running the full microservice

### Prerequisites
- CPython 3.11+
- SQLite 3.37.0+ (`STRICT` mode capability)

### Installation

```bash
git clone https://github.com/invariantzkaedi/zkaedi-authorization-protocol.git
cd zkaedi-authorization-protocol
pip install -r requirements.txt
```

### Run Test Suites & Gauntlets

```bash
# 1. Run 100% Statement Coverage Suite (42/42 PASS, 0 Warnings)
pytest -v --cov=src --cov-report=term-missing --cov-fail-under=100 tests/

# 2. Run 10,000 Mutation Adversarial Fuzz Gauntlet
python tests/fuzz_adversarial_gauntlet.py

# 3. Run Multi-Worker Concurrency & Latency Benchmarks
python tests/benchmark_concurrency_latency.py
```

### Launch Local API Server

```bash
uvicorn src.api_service:app --reload --port 8000
```

Inspect interactive OpenAPI documentation at `http://127.0.0.1:8000/docs`.

---

## 🌐 API Reference

| Domain | Method | Endpoint | Description |
|---|---|---|---|
| **System** | `GET` | `/health` | Service health & version check |
| **Tokens & Transfers** | `POST` | `/api/v1/auth/issue` | Issue context-bound Ed25519 tokens |
| | `POST` | `/api/v1/auth/transfer` | Execute linearizable transfers & return signed receipts |
| **Principals & Issuers** | `POST` | `/api/v1/principal/init` | Initialize principal authority state |
| | `POST` | `/api/v1/principal/bump-epoch` | Monotonically advance `identity`/`role`/`device`/`session` epochs |
| | `POST` | `/api/v1/issuer/init` | Initialize issuer with baseline epoch |
| | `POST` | `/api/v1/issuer/bump-epoch` | Bump issuer epoch counter |
| **Policy & Accounts** | `POST` | `/api/v1/policy/set` | Canonicalize policy rules & compute SHA-256 digest |
| | `POST` | `/api/v1/account/create` | Create account with minor unit balance |
| | `GET` | `/api/v1/account/{account_id}/balance` | Query current minor unit balance |
| **Keyring & Receipts** | `POST` | `/api/v1/keyring/rotate` | Transition key status (`ACTIVE` $\rightarrow$ `VERIFY_ONLY` $\rightarrow$ `RETIRED`) |
| | `POST` | `/api/v1/keyring/register-public` | Register public key for verification |
| | `GET` | `/api/v1/keyring/{key_id_hex}/can-retire` | Query atomic `can_retire_key()` receipt status |
| | `POST` | `/api/v1/receipts/purge-expired` | Purge expired receipt records |
| **Audit Log** | `GET` | `/api/v1/audit/verify` | Verify HMAC audit hash chain against trusted checkpoints |

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
