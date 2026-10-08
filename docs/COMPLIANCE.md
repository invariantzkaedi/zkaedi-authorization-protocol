# Compliance mapping

ZKAEDI provides technical controls and evidence that can support an organization's control environment. It does not provide certification, establish compliance by itself, or replace the policies, access controls, monitoring, retention, and risk assessments required by an applicable framework.

| Framework control | ZKAEDI capability that may support it | Evidence an auditor can collect |
|---|---|---|
| SOC 2 CC7.2 / CC7.3 | Records configured application actions and provides cryptographic checks for later detection of changes. It does not perform an organization's complete monitoring or incident-response process. | Exported audit rows, an independently retained chain checkpoint, verifier output, and the deployed action-coverage configuration. |
| SOC 2 CC6.1 (key management) | Uses registered Ed25519 receipt-signing keys and encrypted-at-rest local signing seeds protected by the configured audit key. Key rotation and operational access controls remain the operator's responsibility. | `key_records` registry, key purpose/status, rotation procedure and records, and documented protection/rotation of `ZKAEDI_AUDIT_KEY`. |
| HIPAA §164.312(b) (audit controls) | Supports recording and examining selected application actions; it does not ensure all ePHI activity is logged or define retention and review processes. | Selected action list and configuration, event export, verifier result, and documented review/retention evidence. |
| HIPAA §164.312(c)(1) (integrity) | HMAC-chained events and Ed25519 receipts can reveal modifications when checked against trusted keys and externally retained checkpoints. | Offline verifier output, receipt public keys, event export, and a checkpoint held separately from the database. |
| PCI DSS v4.0 Req. 10.2 / 10.3 / 10.5 | Can record configured events and action context, and provides cryptographic integrity checks. The application owner must select required events, retain appropriate detail, restrict access, and implement the remaining logging controls. | Event samples and coverage mapping, chain/signature verification, database access controls, and retention configuration/evidence. |
| ISO/IEC 27001:2022 A.8.15 / A.8.16 | Provides application-level records and integrity verification that may support logging and monitoring processes. It does not provide organizational monitoring or alert handling. | Audit export, verifier output, event-selection policy, and evidence of monitoring/review. |
| EU AI Act Article 12 (high-risk-system logging) | Can provide tamper-evident records of configured backend actions. It does not determine whether a system is high-risk, which events must be logged, or whether records meet all applicable retention and traceability obligations. | Event-selection rationale, recorded action examples, external checkpoint, verifier output, and retention/access procedures. |

## How to produce evidence

Set `ZKAEDI_AUDIT_KEY` securely in the environment used for verification. Run `python -m src.verify_cli <sqlite_path>` against a read-only copy of the database; add `--checkpoint <64-hex-chain-head>` to compare the resulting chain head with a checkpoint retained separately. Keep the database copy, checkpoint, verifier version, output, and public signing-key registry together as evidence.

The existing service also exposes `GET /api/v1/audit/verify?seq_num=<sequence>&cp_hash_hex=<hash>` for online verification of that service's configured audit database. Use the offline CLI for independently checking the `ZkaediMiddleware` database, and do not treat an online response or a database-held checkpoint as independent evidence.
