"""
ZKAEDI Authorization Protocol — Vector 2: High-Concurrency Load & Latency Benchmarks
Profiles:
1. Stateless Ed25519 Token Issuance & Verification Latency Distributions (p50, p90, p95, p99, max)
2. Multi-Worker Concurrent SQLite BEGIN IMMEDIATE Transaction Contention (1, 2, 4, 8, 16 workers)
3. End-to-End Linearizable Engine Pipeline Throughput
"""
from __future__ import annotations

import concurrent.futures
import math
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Any

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.context_bound_epoch_protocol import (
    AuthorizationDatabase,
    CredentialCodec,
    Ed25519KeyRing,
    KeyPurpose,
    LinearizableEngine,
    pack_state,
    canonical_json_object,
)
from src.api_service import (
    AuthorizationServiceApp,
    IssueTokenRequest,
    TransferExecuteRequest,
    CreateAccountRequest,
    InitPrincipalRequest,
    InitIssuerRequest,
)


def calculate_percentiles(latencies_ms: List[float]) -> Dict[str, float]:
    """Calculates exact statistical distribution metrics from per-sample latency timings."""
    if not latencies_ms:
        return {"min": 0, "mean": 0, "p50": 0, "p90": 0, "p95": 0, "p99": 0, "p99_9": 0, "max": 0, "stddev": 0}
    
    sorted_lats = sorted(latencies_ms)
    n = len(sorted_lats)
    mean_val = sum(sorted_lats) / n
    variance = sum((x - mean_val) ** 2 for x in sorted_lats) / n
    stddev = math.sqrt(variance)

    def p(pct: float) -> float:
        idx = min(int(n * (pct / 100.0)), n - 1)
        return sorted_lats[idx]

    return {
        "min": sorted_lats[0],
        "mean": mean_val,
        "p50": p(50),
        "p90": p(90),
        "p95": p(95),
        "p99": p(99),
        "p99_9": p(99.9),
        "max": sorted_lats[-1],
        "stddev": stddev,
    }


def benchmark_stateless_crypto(trials: int = 5000) -> None:
    print(f"\n================================================================================")
    print(f" [VECTOR 2.1] STATELESS CRYPTO PIPELINE: Ed25519 & DIGEST PROFILING ({trials:,} SAMPLES)")
    print(f"================================================================================")

    keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=None)
    issuer = "https://auth.enterprise.net"
    key_id = keyring.generate(issuer)
    principal_binding_key = secrets.token_bytes(32)
    codec = CredentialCodec(keyring, principal_binding_key, deployment_id="us-east-prod")

    principal_id = "usr_crypto_bench"
    packed_state = pack_state(1, 1, 1, 1, 1)
    req_bytes = canonical_json_object({
        "action": "transfer",
        "amount_minor": 1500,
        "source_account": "vault_alpha",
        "destination_account": "vault_omega",
    })
    policy_digest = secrets.token_bytes(32)
    now = 1700000000

    # 1. Profile Token Issuance
    issuance_latencies: List[float] = []
    issued_tokens: List[bytes] = []

    for _ in range(trials):
        t0 = time.perf_counter_ns()
        tok = codec.issue(
            key_id=key_id,
            packed_state=packed_state,
            issuer_epoch=1,
            issued_at=now,
            not_before=now,
            expires_at=now + 300,
            issuer=issuer,
            principal_id=principal_id,
            audience="https://api.vault.net",
            resource="ledger",
            action="transfer",
            request_bytes=req_bytes,
            policy_digest=policy_digest,
        )
        t1 = time.perf_counter_ns()
        issuance_latencies.append((t1 - t0) / 1_000_000.0)  # ms
        issued_tokens.append(tok)

    iss_stats = calculate_percentiles(issuance_latencies)
    iss_ops_sec = trials / (sum(issuance_latencies) / 1000.0)

    print(f"\n--- 1. Token Issuance (Ed25519 Sign + Blake2b/SHA256 Digests + Binary Packing) ---")
    print(f"  * Throughput:  {iss_ops_sec:,.1f} ops/sec")
    print(f"  * Latency (ms): mean={iss_stats['mean']:.4f} | min={iss_stats['min']:.4f} | p50={iss_stats['p50']:.4f} | p95={iss_stats['p95']:.4f} | p99={iss_stats['p99']:.4f} | max={iss_stats['max']:.4f}")
    print(f"  * StdDev:      {iss_stats['stddev']:.4f} ms")

    # 2. Profile Token Verification
    verification_latencies: List[float] = []
    for tok in issued_tokens:
        t0 = time.perf_counter_ns()
        claims = codec.verify(
            tok,
            current_time=now,
            expected_issuer=issuer,
            expected_principal_id=principal_id,
            expected_audience="https://api.vault.net",
            expected_resource="ledger",
            expected_action="transfer",
            expected_request_bytes=req_bytes,
        )
        t1 = time.perf_counter_ns()
        verification_latencies.append((t1 - t0) / 1_000_000.0)

    ver_stats = calculate_percentiles(verification_latencies)
    ver_ops_sec = trials / (sum(verification_latencies) / 1000.0)

    print(f"\n--- 2. Token Verification (Ed25519 Verify + HMAC Digests + State Unpacking) ---")
    print(f"  * Throughput:  {ver_ops_sec:,.1f} ops/sec")
    print(f"  * Latency (ms): mean={ver_stats['mean']:.4f} | min={ver_stats['min']:.4f} | p50={ver_stats['p50']:.4f} | p95={ver_stats['p95']:.4f} | p99={ver_stats['p99']:.4f} | max={ver_stats['max']:.4f}")
    print(f"  * StdDev:      {ver_stats['stddev']:.4f} ms")


def benchmark_sqlite_concurrency(worker_counts: List[int] = [1, 2, 4, 8, 16], total_transfers_per_test: int = 1000) -> None:
    print(f"\n================================================================================")
    print(f" [VECTOR 2.2] CONCURRENT SQLITE BEGIN IMMEDIATE CONTENTION BENCHMARK")
    print(f"================================================================================")

    for num_workers in worker_counts:
        tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db_path = os.path.join(tmp_dir.name, "concurrent_bench.db")
        db = AuthorizationDatabase(db_path)

        issuer = "https://auth.enterprise.net"
        issuer_digest = db.initialize_issuer(issuer, epoch=0)

        cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, db)
        receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, db)

        cred_k_id = cred_keyring.generate(issuer)
        receipt_k_id = receipt_keyring.generate(issuer)

        binding_key = secrets.token_bytes(32)
        audit_key = secrets.token_bytes(32)
        codec = CredentialCodec(cred_keyring, binding_key, "us-east-prod")
        engine = LinearizableEngine(db, codec, audit_key, receipt_keyring, receipt_k_id)

        policy_name = "default_policy"
        policy_digest = db.set_policy(policy_name, b'{"allow": true}')

        # Setup accounts and principals
        db.create_account("acct_source", 100_000_000)
        db.create_account("acct_dest", 100_000_000)

        # Pre-issue unique tokens for each transfer
        transfers_per_worker = total_transfers_per_test // num_workers
        worker_payloads: List[List[bytes]] = []
        now = int(time.time())

        for w_idx in range(num_workers):
            w_tokens: List[Any] = []
            p_id = f"usr_worker_{w_idx}"
            p_state = pack_state(w_idx + 1, 1, 1, 1, 1)
            db.initialize_principal(p_id, p_state)

            for t_idx in range(transfers_per_worker):
                req_bytes = canonical_json_object({
                    "action": "transfer",
                    "amount_minor": 10,
                    "source_account": "acct_source",
                    "destination_account": "acct_dest",
                })
                tok = codec.issue(
                    key_id=cred_k_id,
                    packed_state=p_state,
                    issuer_epoch=0,
                    issued_at=now,
                    not_before=now,
                    expires_at=now + 600,
                    issuer=issuer,
                    principal_id=p_id,
                    audience="https://api.vault.net",
                    resource="ledger",
                    action="transfer",
                    request_bytes=req_bytes,
                    policy_digest=policy_digest,
                    credential_id=secrets.token_bytes(16),
                )
                w_tokens.append((tok, req_bytes, p_id))
            worker_payloads.append(w_tokens)

        # Execute concurrent worker threads
        latencies_ms: List[float] = []

        def worker_task(worker_id: int, tasks: List[Any]) -> List[float]:
            worker_lats: List[float] = []
            for tok, req_bytes, p_id in tasks:
                t0 = time.perf_counter_ns()
                res = engine.execute_transfer(
                    tok,
                    current_time=now,
                    expected_issuer=issuer,
                    expected_principal_id=p_id,
                    expected_audience="https://api.vault.net",
                    expected_resource="ledger",
                    expected_action="transfer",
                    expected_request_bytes=req_bytes,
                    expected_policy_name=policy_name,
                )
                t1 = time.perf_counter_ns()
                worker_lats.append((t1 - t0) / 1_000_000.0)
            return worker_lats

        bench_start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [
                executor.submit(worker_task, i, worker_payloads[i])
                for i in range(num_workers)
            ]
            for f in concurrent.futures.as_completed(futures):
                latencies_ms.extend(f.result())

        total_elapsed = time.perf_counter() - bench_start
        stats = calculate_percentiles(latencies_ms)
        tps = len(latencies_ms) / total_elapsed

        print(f"\n--- [{num_workers} Workers Concurrent BEGIN IMMEDIATE ({len(latencies_ms):,} Tx)] ---")
        print(f"  * Total Time:  {total_elapsed:.3f} s")
        print(f"  * Throughput:  {tps:,.1f} committed tx/s")
        print(f"  * Latency (ms): mean={stats['mean']:.3f} | p50={stats['p50']:.3f} | p90={stats['p90']:.3f} | p95={stats['p95']:.3f} | p99={stats['p99']:.3f} | max={stats['max']:.3f}")
        print(f"  * Lock Stdev:  {stats['stddev']:.3f} ms")

        # Verify audit chain consistency after concurrent run
        valid, audit_cnt, _ = db.verify_audit_log(audit_key)
        print(f"  * Audit Chain: {'[VERIFIED IMMUTABLE]' if valid else '[CORRUPT]'} ({audit_cnt:,} sequential blocks verified)")

        try:
            tmp_dir.cleanup()
        except Exception:
            pass


def benchmark_end_to_end_service(trials: int = 1000) -> None:
    print(f"\n================================================================================")
    print(f" [VECTOR 2.3] END-TO-END SERVICE PIPELINE (ISSUE + EXECUTE + RECEIPT)")
    print(f"================================================================================")

    service = AuthorizationServiceApp()
    try:
        issuer = "https://auth.net"
        principal_id = "usr_e2e_bench"
        service.init_principal(InitPrincipalRequest(principal_id=principal_id, role=1))
        service.create_account(CreateAccountRequest(account_id="e2e_source", balance_minor=50_000_000))
        service.create_account(CreateAccountRequest(account_id="e2e_dest", balance_minor=50_000_000))

        e2e_latencies: List[float] = []
        valid_request_dict = {
            "action": "transfer",
            "amount_minor": 100,
            "source_account": "e2e_source",
            "destination_account": "e2e_dest",
        }

        for _ in range(trials):
            t0 = time.perf_counter_ns()
            # 1. Issue token
            iss_res = service.issue_token(
                IssueTokenRequest(
                    issuer=issuer,
                    principal_id=principal_id,
                    audience="https://api.net",
                    resource="vault",
                    action="transfer",
                    request_dict=valid_request_dict,
                    policy_name="default_policy",
                    lifetime_seconds=300,
                )
            )
            token_hex = iss_res["token_hex"]

            # 2. Execute transfer
            exec_res = service.execute_transfer(
                TransferExecuteRequest(
                    token_hex=token_hex,
                    issuer=issuer,
                    principal_id=principal_id,
                    audience="https://api.net",
                    resource="vault",
                    action="transfer",
                    request_dict=valid_request_dict,
                    policy_name="default_policy",
                )
            )
            t1 = time.perf_counter_ns()
            e2e_latencies.append((t1 - t0) / 1_000_000.0)

        e2e_stats = calculate_percentiles(e2e_latencies)
        tps = trials / (sum(e2e_latencies) / 1000.0)

        print(f"  * Pipeline Throughput: {tps:,.1f} completed workflows/s")
        print(f"  * Latency (ms):        mean={e2e_stats['mean']:.3f} | p50={e2e_stats['p50']:.3f} | p95={e2e_stats['p95']:.3f} | p99={e2e_stats['p99']:.3f} | max={e2e_stats['max']:.3f}")
        print(f"  * Distribution:        stddev={e2e_stats['stddev']:.3f} ms")

        audit_res = service.verify_audit_log()
        print(f"  * Audit Verification:  {'[PASS]' if audit_res['valid'] else '[FAIL]'} (Count: {audit_res['count']:,})")
    finally:
        service.cleanup()


if __name__ == "__main__":
    benchmark_stateless_crypto(trials=5000)
    benchmark_sqlite_concurrency(worker_counts=[1, 2, 4, 8, 16], total_transfers_per_test=1000)
    benchmark_end_to_end_service(trials=1000)
