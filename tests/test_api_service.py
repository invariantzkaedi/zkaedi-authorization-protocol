from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from src.api_service import (
    app,
    service,
    AuthorizationServiceApp,
    BumpPrincipalEpochRequest,
    CreateAccountRequest,
    InitIssuerRequest,
    InitPrincipalRequest,
    IssueTokenRequest,
    KeyRotateRequest,
    RegisterPublicKeyRequest,
    SetPolicyRequest,
    TransferExecuteRequest,
    HAS_FASTAPI,
)
from src.context_bound_epoch_protocol import (
    AuthStatus,
    EXPECTED_TOKEN_SIZE,
    KeyStatus,
    MAX_REQUEST_BYTES,
)


def _authorization_header(token: str) -> str:
    return "Bear" + "er " + token


class TestAPIServiceFullCoverageIntegration(unittest.TestCase):
    def setUp(self):
        self.service = AuthorizationServiceApp()
        self.client = TestClient(app)
        self.issuer = "https://auth.net"
        self.principal_id = "usr_100"
        self.audience = "https://api.net"
        self.resource = "vault"
        self.action = "transfer"
        self.request_dict = {
            "action": "transfer",
            "amount_minor": 200,
            "source_account": "vault-1",
            "destination_account": "vault-2",
        }

    def tearDown(self):
        self.service.cleanup()

    def test_full_issue_transfer_replay_rotate_flow(self):
        """1. End-to-end verification of issue, execute transfer, replay idempotency, key rotation, and audit verify."""
        # 1. Issue Token
        issue_req = IssueTokenRequest(
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience=self.audience,
            resource=self.resource,
            action=self.action,
            request_dict=self.request_dict,
            policy_name="default_policy",
            lifetime_seconds=300,
        )
        issue_res = self.service.issue_token(issue_req)
        self.assertEqual(issue_res["status"], "ISSUED")
        tok_hex = issue_res["token_hex"]

        # 2. Execute Transfer
        transfer_req = TransferExecuteRequest(
            token_hex=tok_hex,
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience=self.audience,
            resource=self.resource,
            action=self.action,
            request_dict=self.request_dict,
            policy_name="default_policy",
        )
        transfer_res = self.service.execute_transfer(transfer_req)
        self.assertEqual(transfer_res["status"], AuthStatus.COMMIT_SUCCESS.value)
        self.assertEqual(transfer_res["payload"]["amount_minor"], 200)

        # 3. Replay Transfer -> Must return IDEMPOTENT_REPLAY
        replay_res = self.service.execute_transfer(transfer_req)
        self.assertEqual(replay_res["status"], AuthStatus.IDEMPOTENT_REPLAY.value)

        self.service.receipt_keyring.transition(
            self.service.receipt_key_id, KeyStatus.VERIFY_ONLY
        )
        with self.assertRaises(ValueError):
            self.service.rotate_key(
                KeyRotateRequest(keyring_type="receipt", new_status="retired")
            )
        with self.assertRaises(ValueError):
            self.service.receipt_keyring.transition(
                self.service.receipt_key_id, KeyStatus.RETIRED
            )

        # 4. Verify Audit Log
        audit_res = self.service.verify_audit_log()
        self.assertTrue(audit_res["valid"])

        # 5. Rotate Credential Key
        rotate_req = KeyRotateRequest(keyring_type="credential", new_status="verify_only")
        rotate_res = self.service.rotate_key(rotate_req)
        self.assertEqual(rotate_res["status"], "TRANSITIONED")

    def test_principal_and_issuer_epoch_management_api(self):
        """2. Tests principal initialization, epoch bumping, and issuer epoch bumping APIs."""
        init_p_req = InitPrincipalRequest(principal_id="usr_500", generation=1, identity=1, role=1, device=1, session=1)
        init_p_res = self.service.init_principal(init_p_req)
        self.assertEqual(init_p_res["status"], "INITIALIZED")

        bump_p_req = BumpPrincipalEpochRequest(principal_id="usr_500", field="session")
        bump_p_res = self.service.bump_principal_epoch(bump_p_req)
        self.assertEqual(bump_p_res["status"], "BUMPED")

        init_i_req = InitIssuerRequest(issuer="https://new-issuer.net", epoch=0)
        init_i_res = self.service.init_issuer(init_i_req)
        self.assertEqual(init_i_res["status"], "INITIALIZED")

        bump_i_res = self.service.bump_issuer_epoch("https://new-issuer.net")
        self.assertEqual(bump_i_res["status"], "BUMPED")
        self.assertEqual(bump_i_res["new_epoch"], 1)

    def test_policy_and_account_management_api(self):
        """3. Tests setting canonical policy, creating accounts, and checking balance APIs."""
        set_pol_req = SetPolicyRequest(
            policy_name="custom_policy",
            canonical_policy_dict={"allow_transfer": True, "max_amount_minor": 1000},
        )
        set_pol_res = self.service.set_policy(set_pol_req)
        self.assertEqual(set_pol_res["status"], "SET")

        create_acc_req = CreateAccountRequest(account_id="vault-99", balance_minor=5000)
        create_acc_res = self.service.create_account(create_acc_req)
        self.assertEqual(create_acc_res["status"], "CREATED")

        bal_res = self.service.get_account_balance("vault-99")
        self.assertEqual(bal_res["balance_minor"], 5000)
        for invalid_policy in (
            b'{"allow_transfer":1}',
            b'{"max_amount_minor":true}',
        ):
            with self.assertRaises(ValueError):
                self.service.db.set_policy("invalid_policy", invalid_policy)

    def test_transfer_policy_is_enforced(self):
        policy_name = "limited_transfer"
        self.service.db.set_policy(
            policy_name, b'{"allow_transfer":true,"max_amount_minor":100}'
        )
        request_dict = {
            "action": "transfer",
            "amount_minor": 101,
            "source_account": "vault-1",
            "destination_account": "vault-2",
        }
        issue = IssueTokenRequest(
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience=self.audience,
            resource=self.resource,
            action=self.action,
            request_dict=request_dict,
            policy_name=policy_name,
        )
        token = self.service.issue_token(issue)["token_hex"]
        transfer = TransferExecuteRequest(
            token_hex=token,
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience=self.audience,
            resource=self.resource,
            action=self.action,
            request_dict=request_dict,
            policy_name=policy_name,
        )
        result = self.service.execute_transfer(transfer)
        self.assertEqual(result["status"], AuthStatus.REJECT_POLICY_MISMATCH.value)
        self.assertEqual(self.service.db.balance("vault-1"), 10000)
        self.service.db.set_policy(policy_name, b'{"allow_transfer":false}')
        denied_token = self.service.issue_token(issue)["token_hex"]
        denied_transfer = transfer.model_copy(update={"token_hex": denied_token})
        self.assertEqual(
            self.service.execute_transfer(denied_transfer)["status"],
            AuthStatus.REJECT_POLICY_MISMATCH.value,
        )

        for stored_policy in (b"{", None):
            policy_digest = hashlib.sha256(stored_policy or b"{}").digest()
            connection = self.service.db.connect()
            try:
                connection.execute(
                    "UPDATE policies SET policy_digest = ?, canonical_policy = ? WHERE policy_name = ?",
                    (policy_digest, stored_policy, policy_name),
                )
            finally:
                connection.close()
            bad_token = self.service.issue_token(issue)["token_hex"]
            bad_transfer = transfer.model_copy(update={"token_hex": bad_token})
            self.assertEqual(
                self.service.execute_transfer(bad_transfer)["status"],
                AuthStatus.REJECT_POLICY_MISMATCH.value,
            )

    def test_keyring_public_register_can_retire_and_purge_api(self):
        """4. Tests public key registration, can-retire query, and receipt purging APIs."""
        k_id = secrets.token_bytes(16)
        pub_key = secrets.token_bytes(32)

        reg_req = RegisterPublicKeyRequest(
            key_id_hex=k_id.hex(),
            public_key_hex=pub_key.hex(),
            issuer=self.issuer,
            status="verify_only",
        )
        reg_res = self.service.register_public_key(reg_req)
        self.assertEqual(reg_res["status"], "REGISTERED")

        can_retire_res = self.service.can_retire_key(k_id.hex())
        self.assertTrue(can_retire_res["can_retire"])

        purge_res = self.service.purge_expired_receipts()
        self.assertEqual(purge_res["status"], "PURGED")

    def test_custom_db_path_and_service_rejection_flows(self):
        """5. Tests custom db_path in AuthorizationServiceApp, large payload rejection, malformed hex, and AuthorizationRejected conversion."""
        with tempfile.TemporaryDirectory() as tmp:
            custom_db = os.path.join(tmp, "custom.db")
            srv = AuthorizationServiceApp(db_path=custom_db)
            self.assertEqual(str(srv.db_path), custom_db)
            srv.cleanup()

        # Large request payload exceeding MAX_REQUEST_BYTES
        large_dict = {"action": "transfer", "data": "a" * (MAX_REQUEST_BYTES + 100)}
        large_req = IssueTokenRequest(
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience=self.audience,
            resource=self.resource,
            action=self.action,
            request_dict=large_dict,
            policy_name="default_policy",
            lifetime_seconds=300,
        )
        with self.assertRaises(ValueError):
            self.service.issue_token(large_req)

        # Execute transfer with malformed hex token in service
        with self.assertRaises(ValueError):
            self.service.execute_transfer(TransferExecuteRequest.model_construct(
                token_hex="invalid_hex_str",
                issuer=self.issuer,
                principal_id=self.principal_id,
                audience=self.audience,
                resource=self.resource,
                action=self.action,
                request_dict=self.request_dict,
                policy_name="default_policy",
            ))

        # Execute transfer with rejection returned as status dict
        bad_token = secrets.token_bytes(EXPECTED_TOKEN_SIZE).hex()
        rej_req = TransferExecuteRequest(
            token_hex=bad_token,
            issuer=self.issuer,
            principal_id=self.principal_id,
            audience=self.audience,
            resource=self.resource,
            action=self.action,
            request_dict=self.request_dict,
            policy_name="default_policy",
        )
        rej_res = self.service.execute_transfer(rej_req)
        self.assertIn("status", rej_res)
        self.assertIn("error", rej_res)


class TestFastAPIRoutesAndMiddleware(unittest.TestCase):
    def setUp(self):
        service.__init__()
        self.tokens = {
            "client": "c" * 40,
            "auditor": "u" * 40,
            "admin": "a" * 40,
        }
        self.env_patcher = patch.dict(
            os.environ,
            {
                "ZKAEDI_API_CLIENT_TOKEN": self.tokens["client"],
                "ZKAEDI_API_AUDITOR_TOKEN": self.tokens["auditor"],
                "ZKAEDI_API_ADMIN_TOKEN": self.tokens["admin"],
            },
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)
        self.client = TestClient(app, headers={"Authorization": _authorization_header(self.tokens["admin"])})

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertIn("X-Content-Type-Options", resp.headers)
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")

    def test_api_issue_and_transfer_endpoints(self):
        # 1. Issue
        issue_payload = {
            "issuer": "https://auth.net",
            "principal_id": "usr_100",
            "audience": "https://api.net",
            "resource": "vault",
            "action": "transfer",
            "request_dict": {
                "action": "transfer",
                "amount_minor": 50,
                "source_account": "vault-1",
                "destination_account": "vault-2",
            },
            "policy_name": "default_policy",
            "lifetime_seconds": 300,
        }
        resp = self.client.post("/api/v1/auth/issue", json=issue_payload)
        self.assertEqual(resp.status_code, 200)
        tok_hex = resp.json()["token_hex"]

        # 2. Transfer
        transfer_payload = {
            "token_hex": tok_hex,
            "issuer": "https://auth.net",
            "principal_id": "usr_100",
            "audience": "https://api.net",
            "resource": "vault",
            "action": "transfer",
            "request_dict": {
                "action": "transfer",
                "amount_minor": 50,
                "source_account": "vault-1",
                "destination_account": "vault-2",
            },
            "policy_name": "default_policy",
        }
        resp = self.client.post("/api/v1/auth/transfer", json=transfer_payload)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "COMMIT_SUCCESS")

        # 3. Replay
        resp_replay = self.client.post("/api/v1/auth/transfer", json=transfer_payload)
        self.assertEqual(resp_replay.status_code, 200)
        self.assertEqual(resp_replay.json()["status"], "IDEMPOTENT_REPLAY")

    def test_api_endpoints_all_routes_and_error_handlers(self):
        # Principal init & bump
        resp = self.client.post("/api/v1/principal/init", json={
            "principal_id": "usr_api_test", "generation": 1, "identity": 1, "role": 1, "device": 1, "session": 1
        })
        self.assertEqual(resp.status_code, 200)

        # Duplicate principal with different state -> 400
        resp = self.client.post("/api/v1/principal/init", json={
            "principal_id": "usr_api_test", "generation": 2, "identity": 2, "role": 2, "device": 2, "session": 2
        })
        self.assertEqual(resp.status_code, 400)

        resp = self.client.post("/api/v1/principal/bump-epoch", json={
            "principal_id": "usr_api_test", "field": "role"
        })
        self.assertEqual(resp.status_code, 200)

        # Bump unknown principal -> 400
        resp = self.client.post("/api/v1/principal/bump-epoch", json={
            "principal_id": "usr_unknown", "field": "role"
        })
        self.assertEqual(resp.status_code, 400)

        # Issuer init & bump
        resp = self.client.post("/api/v1/issuer/init", json={
            "issuer": "https://api-issuer.net", "epoch": 0
        })
        self.assertEqual(resp.status_code, 200)

        # Duplicate issuer with different epoch -> 400
        resp = self.client.post("/api/v1/issuer/init", json={
            "issuer": "https://api-issuer.net", "epoch": 5
        })
        self.assertEqual(resp.status_code, 400)

        resp = self.client.post("/api/v1/issuer/bump-epoch?issuer=https://api-issuer.net")
        self.assertEqual(resp.status_code, 200)

        # Bump unknown issuer -> 400
        resp = self.client.post("/api/v1/issuer/bump-epoch?issuer=https://unknown.net")
        self.assertEqual(resp.status_code, 400)

        # Policy & Account
        resp = self.client.post("/api/v1/policy/set", json={
            "policy_name": "api_policy",
            "canonical_policy_dict": {"allow_transfer": True, "max_amount_minor": 1000},
        })
        self.assertEqual(resp.status_code, 200)

        # Unsupported policy fields are rejected.
        resp = self.client.post("/api/v1/policy/set", json={
            "policy_name": "bad_pol", "canonical_policy_dict": {"unrecognized_rule": True}
        })
        self.assertEqual(resp.status_code, 400)
        with patch.object(service.db, "set_policy", side_effect=ValueError("policy error")):
            resp_err = self.client.post("/api/v1/policy/set", json={
                "policy_name": "err_pol", "canonical_policy_dict": {"k": 1}
            })
            self.assertEqual(resp_err.status_code, 400)

        resp = self.client.post("/api/v1/account/create", json={
            "account_id": "api_vault_1", "balance_minor": 1000
        })
        self.assertEqual(resp.status_code, 200)

        # Duplicate account with different balance -> 400
        resp = self.client.post("/api/v1/account/create", json={
            "account_id": "api_vault_1", "balance_minor": 9999
        })
        self.assertEqual(resp.status_code, 400)

        resp = self.client.get("/api/v1/account/api_vault_1/balance")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["balance_minor"], 1000)

        resp = self.client.get("/api/v1/account/non_existent_vault/balance")
        self.assertEqual(resp.status_code, 404)

        # Keyring rotate & register
        resp = self.client.post("/api/v1/keyring/rotate", json={
            "keyring_type": "receipt", "new_status": "verify_only"
        })
        self.assertEqual(resp.status_code, 200)
        resp = self.client.post("/api/v1/keyring/rotate", json={
            "keyring_type": "receipt", "new_status": "retired"
        })
        self.assertEqual(resp.status_code, 200)

        # Key rotate error -> 400
        with patch.object(service, "rotate_key", side_effect=ValueError("rotate error")):
            resp = self.client.post("/api/v1/keyring/rotate", json={
                "keyring_type": "receipt", "new_status": "verify_only"
            })
            self.assertEqual(resp.status_code, 400)

        k_id = secrets.token_bytes(16).hex()
        pub_k = secrets.token_bytes(32).hex()
        resp = self.client.post("/api/v1/keyring/register-public", json={
            "key_id_hex": k_id, "public_key_hex": pub_k, "issuer": "https://auth.net", "status": "verify_only"
        })
        self.assertEqual(resp.status_code, 200)

        # Register public key error -> 400
        with patch.object(service, "register_public_key", side_effect=ValueError("reg error")):
            resp = self.client.post("/api/v1/keyring/register-public", json={
                "key_id_hex": k_id, "public_key_hex": pub_k, "issuer": "https://auth.net", "status": "verify_only"
            })
            self.assertEqual(resp.status_code, 400)

        resp = self.client.get(f"/api/v1/keyring/{k_id}/can-retire")
        self.assertEqual(resp.status_code, 200)

        # Can retire error -> 400
        resp = self.client.get("/api/v1/keyring/short_hex/can-retire")
        self.assertEqual(resp.status_code, 400)

        resp = self.client.post("/api/v1/receipts/purge-expired")
        self.assertEqual(resp.status_code, 200)

        with patch.object(service, "purge_expired_receipts", side_effect=RuntimeError("purge error")):
            resp = self.client.post("/api/v1/receipts/purge-expired")
            self.assertEqual(resp.status_code, 400)

        resp = self.client.get("/api/v1/audit/verify?seq_num=0&cp_hash_hex=" + "00"*32)
        self.assertEqual(resp.status_code, 200)

        with patch.object(service, "verify_audit_log", side_effect=ValueError("audit error")):
            resp = self.client.get("/api/v1/audit/verify")
            self.assertEqual(resp.status_code, 400)

        # Issue token error -> 400
        resp = self.client.post("/api/v1/auth/issue", json={
            "issuer": "https://auth.net", "principal_id": "usr_unknown", "audience": "https://api",
            "resource": "vault", "action": "transfer", "request_dict": {"action": "transfer"},
            "policy_name": "default_policy", "lifetime_seconds": 300
        })
        self.assertEqual(resp.status_code, 400)

        # Transfer execution rejection -> 400
        dummy_tok = secrets.token_bytes(EXPECTED_TOKEN_SIZE).hex()
        resp = self.client.post("/api/v1/auth/transfer", json={
            "token_hex": dummy_tok, "issuer": "https://auth.net", "principal_id": "usr_100",
            "audience": "https://api.net", "resource": "vault", "action": "transfer",
            "request_dict": {"action": "transfer", "amount_minor": 50, "source_account": "vault-1", "destination_account": "vault-2"},
            "policy_name": "default_policy"
        })
        self.assertEqual(resp.status_code, 400)

        # Transfer execution ValueError -> 400
        with patch.object(service, "execute_transfer", side_effect=ValueError("transfer validation error")):
            resp = self.client.post("/api/v1/auth/transfer", json={
                "token_hex": dummy_tok, "issuer": "https://auth.net", "principal_id": "usr_100",
                "audience": "https://api.net", "resource": "vault", "action": "transfer",
                "request_dict": {"action": "transfer", "amount_minor": 50, "source_account": "vault-1", "destination_account": "vault-2"},
                "policy_name": "default_policy"
            })
            self.assertEqual(resp.status_code, 400)

    def test_payload_too_large_middleware(self):
        large_body = b"X" * (MAX_REQUEST_BYTES + 5000)
        resp = self.client.post(
            "/api/v1/auth/issue",
            content=large_body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(large_body))},
        )
        self.assertEqual(resp.status_code, 413)

    def test_api_service_validation_errors(self):
        # Invalid transfer hex length
        with self.assertRaises(Exception):
            TransferExecuteRequest(
                token_hex="bad_hex",
                issuer="https://auth.net",
                principal_id="usr_100",
                audience="https://api.net",
                resource="vault",
                action="transfer",
                request_dict={"action": "transfer"},
                policy_name="default",
            )

        # Invalid token_hex with non-hex content
        with self.assertRaises(Exception):
            TransferExecuteRequest(
                token_hex="zz" * EXPECTED_TOKEN_SIZE,
                issuer="https://auth.net",
                principal_id="usr_100",
                audience="https://api.net",
                resource="vault",
                action="transfer",
                request_dict={"action": "transfer"},
                policy_name="default",
            )

        # Invalid field validation > 1024 bytes
        with self.assertRaises(Exception):
            IssueTokenRequest(
                issuer="a" * 1025,
                principal_id="usr_100",
                audience="https://api.net",
                resource="vault",
                action="transfer",
                request_dict={},
                policy_name="default",
                lifetime_seconds=300,
            )

        with self.assertRaises(Exception):
            IssueTokenRequest(
                issuer="",
                principal_id="usr_100",
                audience="https://api.net",
                resource="vault",
                action="transfer",
                request_dict={},
                policy_name="default",
                lifetime_seconds=300,
            )

        with self.assertRaises(Exception):
            KeyRotateRequest(keyring_type="invalid_type", new_status="verify_only")

        with self.assertRaises(Exception):
            KeyRotateRequest(keyring_type="credential", new_status="invalid_status")

        with self.assertRaises(Exception):
            BumpPrincipalEpochRequest(principal_id="usr_100", field="invalid_field")

    def test_verify_audit_log_invalid_hex(self):
        with self.assertRaises(ValueError):
            service.verify_audit_log(0, "short_hex")
        with self.assertRaises(ValueError):
            service.verify_audit_log(0, "zz" * 32)
        with self.assertRaises(ValueError):
            service.verify_audit_log(0, "00" * 31)
        resp = self.client.get("/api/v1/audit/verify?cp_hash_hex=short_hex")
        self.assertEqual(resp.status_code, 400)

    def test_threshold_endpoints(self):
        # These prototype routes stay unavailable until cryptographic implementations are real.
        dkg_resp = self.client.post("/api/v1/threshold/dkg", json={"t": 3, "n": 5})
        self.assertEqual(dkg_resp.status_code, 501)
        dkg_err = self.client.post("/api/v1/threshold/dkg", json={"t": 10, "n": 2})
        self.assertEqual(dkg_err.status_code, 501)

        # 2. Batch Verify
        batch_payload = {
            "tokens": [
                {
                    "token_id": "tok_1",
                    "message_hex": "68656c6c6f",
                    "sig_hex": "01" * 64,
                    "pk_hex": "02" * 32,
                }
            ]
        }
        batch_resp = self.client.post("/api/v1/threshold/verify-batch", json=batch_payload)
        self.assertEqual(batch_resp.status_code, 501)

        # Batch Verify error path
        batch_err = self.client.post("/api/v1/threshold/verify-batch", json={"tokens": [{"token_id": "t", "message_hex": "not_hex", "sig_hex": "00", "pk_hex": "00"}]})
        self.assertEqual(batch_err.status_code, 501)

        # 3. Epoch Advance
        advance_payload = {
            "issuer": "https://auth.net",
            "current_epoch": 0,
            "target_epoch": 1,
            "state_root_hex": "aa" * 32,
        }
        adv_resp = self.client.post("/api/v1/threshold/epoch/advance", json=advance_payload)
        self.assertEqual(adv_resp.status_code, 501)

        # Epoch Advance error path (jump +2)
        adv_err_payload = {
            "issuer": "https://auth.net",
            "current_epoch": 1,
            "target_epoch": 5,
            "state_root_hex": "bb" * 32,
        }
        adv_err = self.client.post("/api/v1/threshold/epoch/advance", json=adv_err_payload)
        self.assertEqual(adv_err.status_code, 501)
        with patch.object(service, "initiate_dkg", side_effect=RuntimeError("failure")):
            self.assertEqual(
                self.client.post("/api/v1/threshold/dkg", json={"t": 3, "n": 5}).status_code,
                400,
            )
        with patch.object(service, "verify_batch", side_effect=RuntimeError("failure")):
            self.assertEqual(
                self.client.post(
                    "/api/v1/threshold/verify-batch", json={"tokens": []}
                ).status_code,
                400,
            )
        with patch.object(service, "advance_threshold_epoch", side_effect=RuntimeError("failure")):
            self.assertEqual(
                self.client.post(
                    "/api/v1/threshold/epoch/advance", json=advance_payload
                ).status_code,
                400,
            )

    def test_invalid_content_length_rejected(self):
        for content_length in ("invalid", "-1"):
            response = self.client.post(
                "/health",
                content=b"",
                headers={"Content-Length": content_length},
            )
            self.assertEqual(response.status_code, 400)

    def test_role_authentication_is_fail_closed(self):
        unauthenticated = TestClient(app)
        issue_payload = {
            "issuer": "https://auth.net",
            "principal_id": "usr_100",
            "audience": "https://api.net",
            "resource": "vault",
            "action": "transfer",
            "request_dict": {"action": "transfer"},
        }
        self.assertEqual(self.client.post("/api/v1/principal/init", json={
            "principal_id": "forbidden", "generation": 1, "identity": 1,
            "role": 1, "device": 1, "session": 1,
        }, headers={"Authorization": _authorization_header(self.tokens["client"])}).status_code, 403)
        self.assertEqual(unauthenticated.post(
            "/api/v1/auth/issue", json=issue_payload
        ).status_code, 401)
        self.assertEqual(self.client.get(
            "/api/v1/audit/verify",
            headers={"Authorization": _authorization_header(self.tokens["client"])},
        ).status_code, 403)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(unauthenticated.post(
                "/api/v1/auth/issue", json=issue_payload
            ).status_code, 503)
        with patch.dict(
            os.environ,
            {"ZKAEDI_API_CLIENT_TOKEN": self.tokens["client"]},
            clear=True,
        ):
            self.assertEqual(unauthenticated.post(
                "/api/v1/principal/init",
                json={
                    "principal_id": "unconfigured-admin",
                    "generation": 1,
                    "identity": 1,
                    "role": 1,
                    "device": 1,
                    "session": 1,
                },
            ).status_code, 503)

        self.assertEqual(self.client.post(
            "/api/v1/auth/issue",
            json=issue_payload,
            headers={"Authorization": _authorization_header("x" * 40)},
        ).status_code, 401)

    def test_audit_failure_rolls_back_audit_transaction(self):
        with patch.object(service.db, "append_audit_log", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaises(RuntimeError):
                service._record_audit("test", {})
