from __future__ import annotations

import json
import secrets
import unittest

from src.api_service import (
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
)
from src.context_bound_epoch_protocol import AuthStatus


class TestAPIServiceFullCoverageIntegration(unittest.TestCase):
    def setUp(self):
        self.service = AuthorizationServiceApp()
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

        # 4. Verify Audit Log
        audit_res = self.service.verify_audit_log()
        self.assertTrue(audit_res["valid"])

        # 5. Rotate Credential Key
        rotate_req = KeyRotateRequest(keyring_type="credential", new_status="verify_only")
        rotate_res = self.service.rotate_key(rotate_req)
        self.assertEqual(rotate_res["status"], "TRANSITIONED")

    def test_principal_and_issuer_epoch_management_api(self):
        """2. Tests principal initialization, epoch bumping, and issuer epoch bumping APIs."""
        # Init principal
        init_p_req = InitPrincipalRequest(principal_id="usr_500", generation=1, identity=1, role=1, device=1, session=1)
        init_p_res = self.service.init_principal(init_p_req)
        self.assertEqual(init_p_res["status"], "INITIALIZED")

        # Bump principal epoch (session)
        bump_p_req = BumpPrincipalEpochRequest(principal_id="usr_500", field="session")
        bump_p_res = self.service.bump_principal_epoch(bump_p_req)
        self.assertEqual(bump_p_res["status"], "BUMPED")

        # Init issuer
        init_i_req = InitIssuerRequest(issuer="https://new-issuer.net", epoch=0)
        init_i_res = self.service.init_issuer(init_i_req)
        self.assertEqual(init_i_res["status"], "INITIALIZED")

        # Bump issuer epoch
        bump_i_res = self.service.bump_issuer_epoch("https://new-issuer.net")
        self.assertEqual(bump_i_res["status"], "BUMPED")
        self.assertEqual(bump_i_res["new_epoch"], 1)

    def test_policy_and_account_management_api(self):
        """3. Tests policy setting, account creation, and balance querying APIs."""
        # Set policy
        policy_req = SetPolicyRequest(policy_name="custom_policy", canonical_policy_dict={"allow_transfer": True, "max_limit": 5000})
        policy_res = self.service.set_policy(policy_req)
        self.assertEqual(policy_res["status"], "SET")
        self.assertTrue(isinstance(policy_res["policy_digest"], str))

        # Create account
        account_req = CreateAccountRequest(account_id="vault-99", balance_minor=7500)
        account_res = self.service.create_account(account_req)
        self.assertEqual(account_res["status"], "CREATED")

        # Get balance
        bal_res = self.service.get_account_balance("vault-99")
        self.assertEqual(bal_res["balance_minor"], 7500)

    def test_keyring_public_register_can_retire_and_purge_api(self):
        """4. Tests public key registration, receipt purge, and can_retire_key API endpoints."""
        k_id_hex = secrets.token_hex(16)
        pub_hex = secrets.token_hex(32)

        reg_req = RegisterPublicKeyRequest(key_id_hex=k_id_hex, public_key_hex=pub_hex, issuer=self.issuer, status="verify_only")
        reg_res = self.service.register_public_key(reg_req)
        self.assertEqual(reg_res["status"], "REGISTERED")

        # Query can_retire_key
        retire_res = self.service.can_retire_key(self.service.receipt_key_id.hex())
        self.assertTrue(isinstance(retire_res["can_retire"], bool))

        # Purge receipts
        purge_res = self.service.purge_expired_receipts()
        self.assertEqual(purge_res["status"], "PURGED")


if __name__ == "__main__":
    unittest.main()
