# ZKAEDI v26.0 Context-Bound Epoch Authorization Engine & REST Microservice

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![SQLite STRICT](https://img.shields.io/badge/SQLite-3.37%2B%20STRICT-green.svg)](https://www.sqlite.org/strictunpack.html)
[![Ed25519 Cryptography](https://img.shields.io/badge/security-Ed25519-red.svg)](https://cryptography.io/)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25%20(ZD--100)-brightgreen.svg)](tests/test_zd100_coverage.py)
[![Adversarial Fuzzing: 10,000 PASS](https://img.shields.io/badge/fuzzing-10%2C000%20mutations-success.svg)](tests/fuzz_adversarial_gauntlet.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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
   Fixed 329-byte binary tokens signed with Ed25519 containing packed principal state, issuer epochs, validity windows, issuer/principal/context digests, and a canonical request digest.
2. **Linearizable Ledger & Replay Idempotency:**
   Executes transfers inside SQLite transactions and generates **Ed25519 commit receipts**. Replaying a token returns `IDEMPOTENT_REPLAY` with the verified receipt without double-executing.
3. **Persistent Key Registry & Native SQLite Triggers:**
   - `key_records_status_guard`: Native trigger preventing SQL-level reactivation of rotated/retired keys (`ACTIVE` $\rightarrow$ `VERIFY_ONLY` $\rightarrow$ `RETIRED`).
   - `key_records_delete_guard`: Native trigger blocking `DELETE FROM key_records`.
4. **Cross-Process Key Synchronization:**
   Signers and verifiers re-sync status with SQLite on every operation, immediately zeroizing in-memory private key material when rotated by a concurrent process.
5. **HMAC Audit Hash Chain:**
   SHA-256 HMAC chain detects modified events and deletions relative to a separately trusted checkpoint.

---

## 📦 v26 Token Wire Format

Tokens are compact, fixed-size binary structures encoded without variable-length delimiters to prevent parser-differential attacks:

| Field Name | Offset | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Protocol Version** | `0` | `1` | Fixed identifier (`0x40`) |
| **Key ID** | `1` | `16` | Credential-signing key identifier |
| **Issuer Epoch** | `17` | `8` | Big-endian uint64 issuer epoch |
| **Packed Principal State** | `25` | `8` | `generation:16`, then identity/role/device/session:12 bits each |
| **Issued At** | `33` | `8` | Unix timestamp in seconds |
| **Not Before** | `41` | `8` | Earliest valid Unix timestamp |
| **Expires At** | `49` | `8` | Exclusive expiry timestamp; maximum lifetime is 900 seconds |
| **Credential ID** | `57` | `16` | Idempotency identifier |
| **Issuer Digest** | `73` | `32` | SHA-256 over the normalized issuer |
| **Principal Digest** | `105` | `32` | HMAC-SHA-256 over the normalized principal |
| **Audience Digest** | `137` | `32` | SHA-256 over the normalized audience |
| **Scope Digest** | `169` | `32` | SHA-256 over resource, action, and deployment ID |
| **Request Digest** | `201` | `32` | SHA-256 over canonical, strict JSON request bytes |
| **Policy Digest** | `233` | `32` | SHA-256 over canonical policy JSON |
| **Ed25519 Signature** | `265` | `64` | Signature over payload bytes `0..264` |
| **Total token size** | — | **`329 bytes`** | Payload plus signature; no extra frame |

---

## 🛡️ Authorization Statuses

The engine returns string-valued `AuthStatus` names; these are not numeric status codes:

The exact values are defined by `AuthStatus` in `src/context_bound_epoch_protocol.py`. They distinguish successful commits and replays from malformed credentials, signature/key/time/context/state/policy rejections, ledger failures, and tampered or unverifiable prior results. The HTTP layer returns these names in JSON response data; it does not assign the numeric codes shown in older versions of this document.

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
policy_digest BLOB NOT NULL,
canonical_policy BLOB NOT NULL
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
token_digest BLOB NOT NULL,
request_digest BLOB NOT NULL,
    principal_digest BLOB NOT NULL,
    result_digest BLOB NOT NULL,
    result_payload BLOB NOT NULL,
    receipt_signature BLOB NOT NULL,
    receipt_key_id BLOB NOT NULL,
committed_at INTEGER NOT NULL,
expires_at INTEGER NOT NULL
) STRICT;

-- Cryptographic Audit HMAC Chain
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    previous_hash BLOB NOT NULL,
    event_hash BLOB NOT NULL,
    payload BLOB NOT NULL
) STRICT;
```

Database schema migrations advance the SQLite `user_version` to 27. Existing policies created before schema 27 have no stored canonical rule body and fail closed at transfer time until each is set again through `/api/v1/policy/set`.

### Transfer policy format

Policies are canonical JSON objects supporting only:

- `allow_transfer`: optional boolean; defaults to `true`.
- `max_amount_minor`: optional positive integer upper bound per transfer.

Unknown fields and invalid types are rejected when setting a policy. The policy body is persisted along with its digest and evaluated against each transfer after the live digest check.

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
├── src/
│   ├── __init__.py
│   ├── api_service.py                   # FastAPI REST Microservice
│   └── context_bound_epoch_protocol.py  # Core Protocol Engine (v26.0)
└── tests/
    ├── benchmark_concurrency_latency.py # Vector 2: Concurrency & Latency Benchmarks
    ├── fuzz_adversarial_gauntlet.py     # Vector 1: 10,000 Adversarial Mutations
    ├── test_api_service.py              # Microservice Route & Integration Suite
    ├── test_protocol.py                 # Core Engine Master Cumulative Suite
    └── test_zd100_coverage.py           # ZD-100 100% Statement Coverage Gauntlet
```

---

## ⚡ Quickstart

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

Configure distinct bearer secrets of at least 32 UTF-8 bytes before use:

```bash
export ZKAEDI_API_CLIENT_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ZKAEDI_API_AUDITOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ZKAEDI_API_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
```

Send the configured token in the `Authorization` header using the `Bearer` authentication scheme. Client credentials authorize issuance, transfer, and balance reads; auditor credentials authorize audit verification; admin credentials authorize all `/api/v1` operations. Missing/weak server configuration fails closed (503); missing credentials return 401 and insufficient roles return 403. `/health` is public. HSTS is only a response header: terminate TLS at a correctly configured trusted proxy or serve TLS directly, and do not expose this local development configuration publicly. The service currently generates signing/binding/audit keys at startup; stable production key custody and restoration are not implemented, so the service is not production-ready.

The threshold DKG, threshold epoch, and previously experimental batch-verification REST operations return HTTP 501 until their threshold protocols have independent, real cryptographic implementations. `src/lockfree_memory_vault.py` is a state prefilter only; it never authorizes a token because it does not verify the Ed25519 signature.

For production deployment, additionally define a managed secret/key provider and rotation/recovery process, TLS and proxy policy, encrypted backups and tested restore, schema migration roll-forward/rollback procedures, monitoring/alerting, and incident response. The bundled service does not implement these deployment controls.

Inspect interactive OpenAPI documentation at `http://127.0.0.1:8000/docs` only in a trusted development environment.

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
| **Threshold crypto** | `POST` | `/api/v1/threshold/dkg` | Disabled (HTTP 501; prototype cryptography is not trusted) |
| | `POST` | `/api/v1/threshold/verify-batch` | Disabled (HTTP 501; use the standalone real Ed25519 verifier only where appropriate) |
| | `POST` | `/api/v1/threshold/epoch/advance` | Disabled (HTTP 501; no validated threshold signer is available) |

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
