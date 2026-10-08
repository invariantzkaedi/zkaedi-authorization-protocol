from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

from zkaedi.context_bound_epoch_protocol import (
    AuthStatus,
    AuthorizationDatabase,
    AuthorizationRejected,
    CredentialCodec,
    Ed25519KeyRing,
    KeyPurpose,
    KeyStatus,
    LinearizableEngine,
    EXPECTED_TOKEN_SIZE,
    MAX_REQUEST_BYTES,
    __version__,
    canonical_json_object,
    _field_digest,
    pack_state,
)
from zkaedi.crypto.dkg import run_dkg
from zkaedi.crypto.batch_verifier import CredentialToken, verify_token_batch_simd
from zkaedi.crypto.frost_signer import FROSTParticipant
from zkaedi.epoch_manager import EpochManager, EpochAdvanceRequest

# Optional FastAPI / Pydantic imports for OpenAPI docs
try:  # pragma: no cover
    from fastapi import FastAPI, HTTPException, Request, Response, status, Query  # pragma: no cover
    from fastapi.middleware.cors import CORSMiddleware  # pragma: no cover
    from pydantic import BaseModel, Field, field_validator  # pragma: no cover
    HAS_FASTAPI = True  # pragma: no cover
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False  # pragma: no cover


class IssueTokenRequest(BaseModel):
    issuer: str = Field(..., json_schema_extra={"example": "https://auth.net"})
    principal_id: str = Field(..., json_schema_extra={"example": "usr_100"})
    audience: str = Field(..., json_schema_extra={"example": "https://api.net"})
    resource: str = Field(..., json_schema_extra={"example": "vault"})
    action: str = Field(..., json_schema_extra={"example": "transfer"})
    request_dict: Dict[str, Any] = Field(..., json_schema_extra={"example": {"action": "transfer", "amount_minor": 100, "source_account": "vault-1", "destination_account": "vault-2"}})
    policy_name: str = Field("default_policy", json_schema_extra={"example": "default_policy"})
    lifetime_seconds: int = Field(300, ge=1, le=900, json_schema_extra={"example": 300})

    @field_validator("issuer", "principal_id", "audience", "resource", "action")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("field cannot be empty or whitespace")
        if len(value.encode("utf-8")) > 1024:
            raise ValueError("field exceeds 1024 UTF-8 byte limit")
        return value.strip()


class TransferExecuteRequest(BaseModel):
    token_hex: str
    issuer: str = Field(..., json_schema_extra={"example": "https://auth.net"})
    principal_id: str = Field(..., json_schema_extra={"example": "usr_100"})
    audience: str = Field(..., json_schema_extra={"example": "https://api.net"})
    resource: str = Field(..., json_schema_extra={"example": "vault"})
    action: str = Field(..., json_schema_extra={"example": "transfer"})
    request_dict: Dict[str, Any] = Field(..., json_schema_extra={"example": {"action": "transfer", "amount_minor": 100, "source_account": "vault-1", "destination_account": "vault-2"}})
    policy_name: str = Field("default_policy", json_schema_extra={"example": "default_policy"})

    @field_validator("token_hex")
    @classmethod
    def validate_hex(cls, value: str) -> str:
        if not value or len(value) != EXPECTED_TOKEN_SIZE * 2:
            raise ValueError(f"invalid credential token length (must be {EXPECTED_TOKEN_SIZE * 2} hex characters)")
        try:
            raw = bytes.fromhex(value)
            if len(raw) != EXPECTED_TOKEN_SIZE:  # pragma: no cover
                raise ValueError("invalid credential token byte length")
        except ValueError:
            raise ValueError("token_hex must be a valid hex string")
        return value


class KeyRotateRequest(BaseModel):
    keyring_type: str = Field(..., json_schema_extra={"example": "credential"})
    new_status: str = Field(..., json_schema_extra={"example": "verify_only"})

    @field_validator("keyring_type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in ("credential", "receipt"):
            raise ValueError("keyring_type must be 'credential' or 'receipt'")
        return value

    @field_validator("new_status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in ("verify_only", "retired"):
            raise ValueError("new_status must be 'verify_only' or 'retired'")
        return value


class InitPrincipalRequest(BaseModel):
    principal_id: str = Field(..., json_schema_extra={"example": "usr_300"})
    generation: int = Field(1, ge=0, le=65535)
    identity: int = Field(1, ge=0, le=4095)
    role: int = Field(1, ge=0, le=4095)
    device: int = Field(1, ge=0, le=4095)
    session: int = Field(1, ge=0, le=4095)


class BumpPrincipalEpochRequest(BaseModel):
    principal_id: str = Field(..., json_schema_extra={"example": "usr_100"})
    field: str = Field(..., json_schema_extra={"example": "session"})

    @field_validator("field")
    @classmethod
    def validate_field(cls, value: str) -> str:
        if value not in ("identity", "role", "device", "session"):
            raise ValueError("field must be 'identity', 'role', 'device', or 'session'")
        return value


class InitIssuerRequest(BaseModel):
    issuer: str = Field(..., json_schema_extra={"example": "https://auth.net"})
    epoch: int = Field(0, ge=0)


class SetPolicyRequest(BaseModel):
    policy_name: str = Field(..., json_schema_extra={"example": "transfer_policy"})
    canonical_policy_dict: Dict[str, Any] = Field(..., json_schema_extra={"example": {"allow_transfer": True, "max_amount": 5000}})


class CreateAccountRequest(BaseModel):
    account_id: str = Field(..., json_schema_extra={"example": "vault-3"})
    balance_minor: int = Field(1000, ge=0, le=9223372036854775807)


class RegisterPublicKeyRequest(BaseModel):
    key_id_hex: str = Field(..., json_schema_extra={"example": "00112233445566778899aabbccddeeff"})
    public_key_hex: str = Field(..., json_schema_extra={"example": "00"*32})
    issuer: str = Field(..., json_schema_extra={"example": "https://auth.net"})
    status: str = Field("verify_only", json_schema_extra={"example": "verify_only"})


class DKGInitiateRequest(BaseModel):
    t: int = Field(3, ge=1, le=100)
    n: int = Field(5, ge=1, le=100)


class BatchVerifyRequest(BaseModel):
    tokens: list[Dict[str, str]] = Field(..., json_schema_extra={"example": [{"token_id": "tok_1", "message_hex": "68656c6c6f", "sig_hex": "00"*64, "pk_hex": "00"*32}]})


class ThresholdEpochAdvanceRequest(BaseModel):
    issuer: str = Field(..., json_schema_extra={"example": "https://auth.net"})
    current_epoch: int = Field(0, ge=0)
    target_epoch: int = Field(1, ge=1)
    state_root_hex: str = Field("00"*32)


class AuthorizationServiceApp:
    """Full-Coverage production service container wrapping 100% of Authorization Engine APIs."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            self._temp_dir = tempfile.TemporaryDirectory()
            self.db_path = Path(self._temp_dir.name) / "auth.db"
        else:
            self._temp_dir = None
            self.db_path = Path(db_path)

        self.db = AuthorizationDatabase(self.db_path)
        self.issuer = "https://auth.net"

        # Credential Keyring with DB synchronization
        self.cred_keyring = Ed25519KeyRing(KeyPurpose.CREDENTIAL_SIGNING, database=self.db)
        self.cred_key_id = self.cred_keyring.generate(self.issuer)

        # Dedicated Receipt Keyring with DB synchronization
        self.receipt_keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, database=self.db)
        self.receipt_key_id = self.receipt_keyring.generate(self.issuer)

        self.p_key = secrets.token_bytes(32)
        self.audit_key = secrets.token_bytes(32)

        self.codec = CredentialCodec(self.cred_keyring, self.p_key, "prod-us-east-1")
        self.engine = LinearizableEngine(
            self.db, self.codec, self.audit_key,
            receipt_keyring=self.receipt_keyring, receipt_key_id=self.receipt_key_id
        )

        # Default policy and initial data setup
        self.policy_name = "default_policy"
        self.policy_bytes = b'{"allow_transfer":true}'
        self.policy_digest = self.db.set_policy(self.policy_name, self.policy_bytes)
        self.db.initialize_issuer(self.issuer, 0)
        self.db.initialize_principal("usr_100", pack_state(1, 1, 1, 1, 1))
        self.db.initialize_principal("usr_200", pack_state(1, 1, 1, 1, 1))
        self.db.create_account("vault-1", 10000)
        self.db.create_account("vault-2", 5000)

    # 1. TOKEN & TRANSFER APIS
    def issue_token(self, req: IssueTokenRequest) -> Dict[str, Any]:
        snap = self.db.issuance_snapshot(req.principal_id, req.issuer, req.policy_name)
        now = int(time.time())
        req_bytes = canonical_json_object(req.request_dict)
        if len(req_bytes) > MAX_REQUEST_BYTES:
            raise ValueError("request payload exceeds maximum policy size")

        tok = self.codec.issue(
            key_id=self.cred_key_id,
            packed_state=snap.packed_state,
            issuer_epoch=snap.issuer_epoch,
            issued_at=now,
            not_before=now,
            expires_at=now + req.lifetime_seconds,
            issuer=req.issuer,
            principal_id=req.principal_id,
            audience=req.audience,
            resource=req.resource,
            action=req.action,
            request_bytes=req_bytes,
            policy_digest=snap.policy_digest,
        )

        return {
            "status": "ISSUED",
            "token_hex": tok.hex(),
            "expires_at": now + req.lifetime_seconds,
            "version": __version__,
        }

    def execute_transfer(self, req: TransferExecuteRequest) -> Dict[str, Any]:
        try:
            tok_bytes = bytes.fromhex(req.token_hex)
        except ValueError as exc:
            raise ValueError("malformed hex token") from exc

        now = int(time.time())
        req_bytes = canonical_json_object(req.request_dict)

        try:
            res = self.engine.execute_transfer(
                tok_bytes,
                current_time=now,
                expected_issuer=req.issuer,
                expected_principal_id=req.principal_id,
                expected_audience=req.audience,
                expected_resource=req.resource,
                expected_action=req.action,
                expected_request_bytes=req_bytes,
                expected_policy_name=req.policy_name,
            )
            return res.to_dict()
        except AuthorizationRejected as cm:
            return {
                "status": cm.status.value,
                "error": str(cm),
            }

    # 2. PRINCIPAL & ISSUER APIS
    def init_principal(self, req: InitPrincipalRequest) -> Dict[str, Any]:
        state = pack_state(req.generation, req.identity, req.role, req.device, req.session)
        self.db.initialize_principal(req.principal_id, state)
        return {"status": "INITIALIZED", "principal_id": req.principal_id, "packed_state": state}

    def bump_principal_epoch(self, req: BumpPrincipalEpochRequest) -> Dict[str, Any]:
        new_state = self.db.bump_principal_epoch(req.principal_id, req.field)
        return {"status": "BUMPED", "principal_id": req.principal_id, "field": req.field, "new_state": new_state}

    def init_issuer(self, req: InitIssuerRequest) -> Dict[str, Any]:
        self.db.initialize_issuer(req.issuer, req.epoch)
        return {"status": "INITIALIZED", "issuer": req.issuer, "epoch": req.epoch}

    def bump_issuer_epoch(self, issuer: str) -> Dict[str, Any]:
        new_epoch = self.db.bump_issuer_epoch(issuer)
        return {"status": "BUMPED", "issuer": issuer, "new_epoch": new_epoch}

    # 3. POLICY & ACCOUNT APIS
    def set_policy(self, req: SetPolicyRequest) -> Dict[str, Any]:
        policy_bytes = canonical_json_object(req.canonical_policy_dict)
        digest = self.db.set_policy(req.policy_name, policy_bytes)
        return {"status": "SET", "policy_name": req.policy_name, "policy_digest": digest.hex()}

    def create_account(self, req: CreateAccountRequest) -> Dict[str, Any]:
        self.db.create_account(req.account_id, req.balance_minor)
        return {"status": "CREATED", "account_id": req.account_id, "balance_minor": req.balance_minor}

    def get_account_balance(self, account_id: str) -> Dict[str, Any]:
        bal = self.db.balance(account_id)
        return {"account_id": account_id, "balance_minor": bal}

    # 4. KEYRING & RECEIPT APIS
    def rotate_key(self, req: KeyRotateRequest) -> Dict[str, Any]:
        target_ring = self.cred_keyring if req.keyring_type == "credential" else self.receipt_keyring
        target_key_id = self.cred_key_id if req.keyring_type == "credential" else self.receipt_key_id
        new_st = KeyStatus(req.new_status)

        target_ring.transition(target_key_id, new_st)
        return {
            "status": "TRANSITIONED",
            "keyring": req.keyring_type,
            "new_status": new_st.value,
        }

    def register_public_key(self, req: RegisterPublicKeyRequest) -> Dict[str, Any]:
        k_id = bytes.fromhex(req.key_id_hex)
        pub_bytes = bytes.fromhex(req.public_key_hex)
        self.cred_keyring.register_public(k_id, pub_bytes, req.issuer, status=KeyStatus(req.status))
        return {"status": "REGISTERED", "key_id_hex": req.key_id_hex}

    def can_retire_key(self, key_id_hex: str) -> Dict[str, Any]:
        k_id = bytes.fromhex(key_id_hex)
        now = int(time.time())
        retirable = self.db.can_retire_key(k_id, now)
        return {"key_id_hex": key_id_hex, "can_retire": retirable}

    def purge_expired_receipts(self) -> Dict[str, Any]:
        now = int(time.time())
        count = self.db.purge_expired_receipts(now)
        return {"status": "PURGED", "purged_count": count}

    # 5. AUDIT LOG VERIFICATION
    def verify_audit_log(self, seq_num: int = 0, cp_hash_hex: str = "00"*32) -> Dict[str, Any]:
        try:
            cp_hash = bytes.fromhex(cp_hash_hex)
            if len(cp_hash) != 32:
                raise ValueError
        except ValueError:
            raise ValueError("cp_hash_hex must be a 64-character hex string")

        checkpoint = (seq_num, cp_hash) if (seq_num != 0 or cp_hash_hex != "00"*32) else (0, b"\x00"*32)
        valid, count, latest_hash = self.db.verify_audit_log(self.audit_key, trusted_checkpoint=checkpoint)
        return {
            "valid": valid,
            "count": count,
            "latest_hash": latest_hash.hex(),
        }

    # THRESHOLD CRYPTO SERVICE METHODS
    def initiate_dkg(self, req: DKGInitiateRequest) -> Dict[str, Any]:
        tr = run_dkg(req.t, req.n)
        return {
            "t": tr.t,
            "n": tr.n,
            "qual_nodes": sorted(list(tr.qual)),
            "group_public_key_hex": tr.group_public_key.hex() if tr.group_public_key else "",
            "verification_shares_count": len(tr.verification_shares),
        }

    def verify_batch(self, req: BatchVerifyRequest) -> Dict[str, Any]:
        tokens = []
        for item in req.tokens:
            tok = CredentialToken(
                token_id=item.get("token_id", "tok"),
                message=bytes.fromhex(item.get("message_hex", "")),
                signature=bytes.fromhex(item.get("sig_hex", "")),
                public_key=bytes.fromhex(item.get("pk_hex", "")),
            )
            tokens.append(tok)
        all_valid, amortized_us, invalid_indices = verify_token_batch_simd(tokens)
        return {
            "all_valid": all_valid,
            "count": len(tokens),
            "amortized_latency_us": round(amortized_us, 4),
            "invalid_indices": invalid_indices,
        }

    def advance_threshold_epoch(self, req: ThresholdEpochAdvanceRequest) -> Dict[str, Any]:
        tr = run_dkg(3, 5)
        mgr = EpochManager(tr, 3, db_path=str(self.db_path))
        parts = [
            FROSTParticipant(i, i * 100, tr.verification_shares.get(i, b"\x00"*32))
            for i in range(1, 4)
        ]
        advance_req = EpochAdvanceRequest(
            issuer_id=req.issuer,
            current_epoch=req.current_epoch,
            target_epoch=req.target_epoch,
            state_root=bytes.fromhex(req.state_root_hex),
        )
        cert = mgr.request_advance(advance_req, parts)
        return {
            "issuer": cert.issuer_id,
            "epoch": cert.epoch,
            "signature_hex": cert.signature.to_bytes().hex(),
            "signers": sorted(list(cert.signer_ids)),
            "issued_at": cert.issued_at,
        }

    def cleanup(self) -> None:
        if self._temp_dir:
            self._temp_dir.cleanup()


# Create FastAPI application if FastAPI is installed
if HAS_FASTAPI:
    service = AuthorizationServiceApp()

    app = FastAPI(
        title="v26.0 Full-Coverage Authorization Microservice",
        description="Complete REST API wrapping 100% of authorization engine operations, principal epochs, policy management, keyring lifecycle, and audit chains.",
        version=__version__,
    )

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BYTES:
            return Response(content="Payload Too Large", status_code=status.HTTP_413_CONTENT_TOO_LARGE)

        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    @app.get("/health")
    def health_check():
        return {"status": "HEALTHY", "version": __version__}

    # TOKEN & TRANSFER ENDPOINTS
    @app.post("/api/v1/auth/issue")
    def api_issue_token(req: IssueTokenRequest):
        try:
            return service.issue_token(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/auth/transfer")
    def api_execute_transfer(req: TransferExecuteRequest):
        try:
            res = service.execute_transfer(req)
            if res.get("status") in (AuthStatus.COMMIT_SUCCESS.value, AuthStatus.IDEMPOTENT_REPLAY.value):
                return res
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # PRINCIPAL & ISSUER ENDPOINTS
    @app.post("/api/v1/principal/init")
    def api_init_principal(req: InitPrincipalRequest):
        try:
            return service.init_principal(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/principal/bump-epoch")
    def api_bump_principal_epoch(req: BumpPrincipalEpochRequest):
        try:
            return service.bump_principal_epoch(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/issuer/init")
    def api_init_issuer(req: InitIssuerRequest):
        try:
            return service.init_issuer(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/issuer/bump-epoch")
    def api_bump_issuer_epoch(issuer: str = Query(...)):
        try:
            return service.bump_issuer_epoch(issuer)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # POLICY & ACCOUNT ENDPOINTS
    @app.post("/api/v1/policy/set")
    def api_set_policy(req: SetPolicyRequest):
        try:
            return service.set_policy(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/account/create")
    def api_create_account(req: CreateAccountRequest):
        try:
            return service.create_account(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.get("/api/v1/account/{account_id}/balance")
    def api_get_account_balance(account_id: str):
        try:
            return service.get_account_balance(account_id)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    # KEYRING & RECEIPT ENDPOINTS
    @app.post("/api/v1/keyring/rotate")
    def api_rotate_key(req: KeyRotateRequest):
        try:
            return service.rotate_key(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/keyring/register-public")
    def api_register_public_key(req: RegisterPublicKeyRequest):
        try:
            return service.register_public_key(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.get("/api/v1/keyring/{key_id_hex}/can-retire")
    def api_can_retire_key(key_id_hex: str):
        try:
            return service.can_retire_key(key_id_hex)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/receipts/purge-expired")
    def api_purge_expired_receipts():
        try:
            return service.purge_expired_receipts()
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # THRESHOLD CRYPTO ENDPOINTS
    @app.post("/api/v1/threshold/dkg")
    def api_initiate_dkg(req: DKGInitiateRequest):
        try:
            return service.initiate_dkg(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/threshold/verify-batch")
    def api_verify_batch(req: BatchVerifyRequest):
        try:
            return service.verify_batch(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    @app.post("/api/v1/threshold/epoch/advance")
    def api_advance_threshold_epoch(req: ThresholdEpochAdvanceRequest):
        try:
            return service.advance_threshold_epoch(req)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # AUDIT LOG ENDPOINT
    @app.get("/api/v1/audit/verify")
    def api_verify_audit(seq_num: int = Query(0, ge=0), cp_hash_hex: str = Query("00"*32)):
        try:
            return service.verify_audit_log(seq_num, cp_hash_hex)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
