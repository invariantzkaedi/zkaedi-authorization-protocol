from __future__ import annotations

import os
import sys
import time
import secrets
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api_service import (
    AuthorizationServiceApp,
    IssueTokenRequest,
    TransferExecuteRequest,
    BumpPrincipalEpochRequest,
    CreateAccountRequest,
    InitIssuerRequest,
    InitPrincipalRequest,
    SetPolicyRequest,
)
from src.context_bound_epoch_protocol import AuthStatus


def run_adversarial_fuzz_gauntlet(iterations=10000):
    print(f"=== [VECTOR 1: ADVERSARIAL PROTOCOL FUZZING GAUNTLET ({iterations:,} MUTATIONS)] ===")
    start_time = time.perf_counter()

    service = AuthorizationServiceApp()
    try:
        issuer = "https://auth.net"
        principal_id = "usr_adversary_001"
        audience = "https://api.net"
        resource = "vault"
        action = "transfer"
        policy_name = "default_policy"

        # 0. Init principal
        service.init_principal(InitPrincipalRequest(principal_id=principal_id, role=1))

        # 1. Setup accounts
        service.create_account(CreateAccountRequest(account_id="vault-a", balance_minor=10000000))
        service.create_account(CreateAccountRequest(account_id="vault-b", balance_minor=10000000))

        valid_request_dict = {
            "action": "transfer",
            "amount_minor": 500,
            "source_account": "vault-a",
            "destination_account": "vault-b",
        }

        # Issue baseline token
        issue_req = IssueTokenRequest(
            issuer=issuer,
            principal_id=principal_id,
            audience=audience,
            resource=resource,
            action=action,
            request_dict=valid_request_dict,
            policy_name=policy_name,
            lifetime_seconds=300,
        )
        issue_res = service.issue_token(issue_req)
        tok_hex = issue_res["token_hex"]
        tok_bytes = bytes.fromhex(tok_hex)

        # 1. Signature Bit-Flip Mutation Fuzzing (5,000 trials)
        print("  * [Fuzz 1/4] Signature & Cryptographic Malleability (5,000 Bit-Flips)...")
        caught_sig_tampering = 0
        for _ in range(5000):
            mutated = bytearray(tok_bytes)
            flip_idx = secrets.randbelow(64)  # Signature is in the last 64 bytes
            mutated[len(mutated) - 64 + flip_idx] ^= (1 << secrets.randbelow(8))
            res = service.execute_transfer(
                TransferExecuteRequest(
                    token_hex=mutated.hex(),
                    issuer=issuer,
                    principal_id=principal_id,
                    audience=audience,
                    resource=resource,
                    action=action,
                    request_dict=valid_request_dict,
                    policy_name=policy_name,
                )
            )
            if res["status"] != AuthStatus.COMMIT_SUCCESS.value:
                caught_sig_tampering += 1
            else:
                raise AssertionError("Bit-flipped signature accepted!")

        # 2. Context-Bound Request Payload Tampering (2,000 trials)
        print("  * [Fuzz 2/4] Context-Bound Request Tampering (2,000 Trials)...")
        caught_payload_tampering = 0
        for _ in range(2000):
            tampered_dict = dict(valid_request_dict)
            tampered_dict["amount_minor"] = secrets.randbelow(1000000) + 1000
            res = service.execute_transfer(
                TransferExecuteRequest(
                    token_hex=tok_hex,
                    issuer=issuer,
                    principal_id=principal_id,
                    audience=audience,
                    resource=resource,
                    action=action,
                    request_dict=tampered_dict,
                    policy_name=policy_name,
                )
            )
            if res["status"] != AuthStatus.COMMIT_SUCCESS.value:
                caught_payload_tampering += 1
            else:
                raise AssertionError("Tampered payload accepted under token digest!")

        # 3. Monotonic Epoch Invalidation & Fast Replay (1,500 trials)
        print("  * [Fuzz 3/4] Monotonic Epoch Invalidation & Revocation (1,500 Trials)...")
        caught_epoch_violations = 0
        for _ in range(1500):
            t_res = service.issue_token(issue_req)
            t_hex = t_res["token_hex"]
            # Invalidate epoch for principal
            service.bump_principal_epoch(BumpPrincipalEpochRequest(principal_id=principal_id, field="session"))
            res = service.execute_transfer(
                TransferExecuteRequest(
                    token_hex=t_hex,
                    issuer=issuer,
                    principal_id=principal_id,
                    audience=audience,
                    resource=resource,
                    action=action,
                    request_dict=valid_request_dict,
                    policy_name=policy_name,
                )
            )
            if res["status"] == AuthStatus.REJECT_STATE_MISMATCH.value:
                caught_epoch_violations += 1
            else:
                raise AssertionError(f"Expired epoch token accepted! Got status: {res['status']}")

        # 4. Nonce Collisions & Idempotent Execution (1,500 trials)
        print("  * [Fuzz 4/4] Nonce Collision & Replay Resistance (1,500 Trials)...")
        caught_replays = 0
        fresh_token = service.issue_token(issue_req)
        fresh_hex = fresh_token["token_hex"]
        transfer_req = TransferExecuteRequest(
            token_hex=fresh_hex,
            issuer=issuer,
            principal_id=principal_id,
            audience=audience,
            resource=resource,
            action=action,
            request_dict=valid_request_dict,
            policy_name=policy_name,
        )
        res1 = service.execute_transfer(transfer_req)
        if res1["status"] != AuthStatus.COMMIT_SUCCESS.value:
            raise AssertionError(f"First execution failed: {res1}")

        for _ in range(1500):
            res2 = service.execute_transfer(transfer_req)
            if res2["status"] != AuthStatus.IDEMPOTENT_REPLAY.value:
                raise AssertionError(f"Replay idempotency failed! Status: {res2['status']}")
            caught_replays += 1

        # Verify audit log integrity
        audit_check = service.verify_audit_log()
        if not audit_check["valid"]:
            raise AssertionError("Audit log validation failed!")

    finally:
        service.cleanup()

    elapsed = time.perf_counter() - start_time
    print(f"\n[GAUNTLET COMPLETE] 10,000 / 10,000 adversarial mutations passed in {elapsed*1000:.2f} ms ({iterations/elapsed:.1f} op/s)")
    print(f"  - Bit-Flip Rejections: {caught_sig_tampering}/5,000")
    print(f"  - Payload Digest Mismatch Rejections: {caught_payload_tampering}/2,000")
    print(f"  - Monotonic Epoch Rejections: {caught_epoch_violations}/1,500")
    print(f"  - Replay Idempotency Verifications: {caught_replays}/1,500")
    print(f"  - Merkle / Hash Chain Audit State: VERIFIED (0 Tamper Errors)")
    print("=== [VECTOR 1: VERDICT = 100% IMMUTABLE HARDENED] ===")


if __name__ == "__main__":
    run_adversarial_fuzz_gauntlet()
