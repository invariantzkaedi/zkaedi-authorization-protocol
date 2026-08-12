# ZKAEDI v26.0 Context-Bound Epoch Authorization Engine & REST Microservice

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![SQLite STRICT](https://img.shields.io/badge/SQLite-3.37%2B%20STRICT-green.svg)](https://www.sqlite.org/strictunpack.html)
[![Ed25519 Cryptography](https://img.shields.io/badge/security-Ed25519-red.svg)](https://cryptography.io/)
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
   Fixed 249-byte tokens signed with Ed25519 key pairs containing 64-bit packed epoch state, validity time windows, issuer digests, principal digests, and request HMACs.

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
    ├── test_api_service.py              # Microservice Integration Suite (4/4 PASS)
    └── test_protocol.py                 # Core Engine Master Suite (10/10 PASS)
```

---

## ⚡ Quickstart

### Prerequisites
- CPython 3.11+
- SQLite 3.37.0+ (`STRICT` mode capability)

### Installation

```bash
git clone https://github.com/your-username/zkaedi-authorization-protocol.git
cd zkaedi-authorization-protocol
pip install -r requirements.txt
```

### Run Tests

```bash
# Run Core Protocol Engine Tests (10/10 PASS)
python -m unittest tests/test_protocol.py -v

# Run REST Microservice Tests (4/4 PASS)
python -m unittest tests/test_api_service.py -v
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
