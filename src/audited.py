from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import hmac
import inspect
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from src.context_bound_epoch_protocol import (
    AuthorizationDatabase,
    Ed25519KeyRing,
    KeyPurpose,
    KeyStatus,
    canonical_json_object,
)


class IdempotencyConflict(Exception):
    pass


@dataclass(frozen=True)
class AuditReceipt:
    signature: bytes
    sequence: int
    entry_hash: bytes
    key_id: bytes

    def headers(self) -> dict[str, str]:
        return {
            "X-Zkaedi-Receipt-Sig": base64.b64encode(self.signature).decode("ascii"),
            "X-Zkaedi-Chain-Index": str(self.sequence),
            "X-Zkaedi-Entry-Hash": self.entry_hash.hex(),
            "X-Zkaedi-Key-Id": self.key_id.hex(),
        }


@dataclass
class _RequestContext:
    request: Any
    body: Any
    recorder: "AuditRecorder"
    principal_resolver: Callable[[Any], str]
    receipt: AuditReceipt | None = None


_request_context: contextvars.ContextVar[_RequestContext | None] = contextvars.ContextVar(
    "zkaedi_audit_request", default=None
)


class AuditRecorder:
    """Framework-agnostic writer for signed audit events and idempotent responses."""

    def __init__(
        self,
        sqlite_path: str | os.PathLike[str],
        service_name: str,
        audit_key: bytes | str | None = None,
    ) -> None:
        if not service_name:
            raise ValueError("service_name must be non-empty")
        if audit_key is None:
            audit_key = os.environ.get("ZKAEDI_AUDIT_KEY")
        if isinstance(audit_key, str):
            try:
                audit_key = bytes.fromhex(audit_key)
            except ValueError as exc:
                raise ValueError("ZKAEDI_AUDIT_KEY must be a hexadecimal key") from exc
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise ValueError("audit_key must contain at least 32 bytes")
        self.database = AuthorizationDatabase(sqlite_path)
        self.service_name = service_name
        self.audit_key = bytes(audit_key)
        self.keyring = Ed25519KeyRing(KeyPurpose.RECEIPT_SIGNING, database=self.database)
        self._initialize_tables()
        self.key_id = self._load_or_create_key()

    def _encryption_key(self) -> bytes:
        return hmac.digest(
            self.audit_key,
            b"zkaedi-receipt-private-key-v1\x00" + self.service_name.encode("utf-8"),
            hashlib.sha256,
        )

    def _initialize_tables(self) -> None:
        connection = self.database.connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS zkaedi_receipt_private_keys (
                    key_id BLOB PRIMARY KEY,
                    nonce BLOB NOT NULL,
                    encrypted_seed BLOB NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS zkaedi_receipts (
                    sequence INTEGER PRIMARY KEY,
                    key_id BLOB NOT NULL,
                    signature BLOB NOT NULL,
                    signed_payload BLOB NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS zkaedi_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    context_digest BLOB NOT NULL,
                    state TEXT NOT NULL,
                    response BLOB
                ) STRICT;
                """
            )
        finally:
            connection.close()

    def _load_or_create_key(self) -> bytes:
        connection = self.database.connect()
        try:
            keys = connection.execute(
                "SELECT k.key_id, p.nonce, p.encrypted_seed FROM key_records k "
                "JOIN zkaedi_receipt_private_keys p ON p.key_id = k.key_id "
                "WHERE k.purpose = 'receipt_signing' AND k.status = 'active' ORDER BY k.rowid DESC"
            ).fetchall()
        finally:
            connection.close()
        encryption_key = self._encryption_key()
        for key_id, nonce, encrypted_seed in keys:
            try:
                seed = AESGCM(encryption_key).decrypt(
                    nonce, encrypted_seed, self.service_name.encode("utf-8") + key_id
                )
                self.keyring.register_private(key_id, seed, self.service_name)
                return key_id
            except (ValueError, KeyError, InvalidTag):
                continue
        private_key = Ed25519PrivateKey.generate()
        seed = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        key_id = secrets.token_bytes(16)
        self.keyring.register_private(key_id, seed, self.service_name, KeyStatus.ACTIVE)
        nonce = secrets.token_bytes(12)
        encrypted_seed = AESGCM(encryption_key).encrypt(
            nonce, seed, self.service_name.encode("utf-8") + key_id
        )
        connection = self.database.connect()
        try:
            connection.execute(
                "INSERT INTO zkaedi_receipt_private_keys(key_id, nonce, encrypted_seed) VALUES(?, ?, ?)",
                (key_id, nonce, encrypted_seed),
            )
        finally:
            connection.close()
        return key_id

    @staticmethod
    def context_digest(
        principal_id: str, action: str, resource: Any, request_body: Any
    ) -> bytes:
        return hashlib.sha256(
            canonical_json_object(
                {
                    "principal_id": principal_id,
                    "action": action,
                    "resource": resource,
                    "request_body": request_body,
                }
            )
        ).digest()

    def lookup_idempotency(self, key: str, context_digest: bytes) -> bytes | None:
        connection = self.database.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT context_digest, state, response FROM zkaedi_idempotency WHERE idempotency_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO zkaedi_idempotency(idempotency_key, context_digest, state) "
                    "VALUES(?, ?, 'pending')",
                    (key, context_digest),
                )
                connection.commit()
                return None
            if not hmac.compare_digest(row[0], context_digest):
                connection.rollback()
                raise IdempotencyConflict()
            if row[1] != "committed" or row[2] is None:
                connection.rollback()
                raise IdempotencyConflict()
            connection.commit()
            return row[2]
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise IdempotencyConflict() from exc
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def discard_idempotency(self, key: str | None) -> None:
        if key is None:
            return
        connection = self.database.connect()
        try:
            connection.execute(
                "DELETE FROM zkaedi_idempotency WHERE idempotency_key = ? AND state = 'pending'",
                (key,),
            )
        finally:
            connection.close()

    def record(
        self,
        *,
        principal_id: str,
        action: str,
        resource: Any,
        request_body: Any,
        status_code: int | str,
        response_body: bytes,
        latency_ms: float,
        context_digest: bytes | None = None,
        idempotency_key: str | None = None,
        cached_response: bytes | None = None,
        severity: str = "INFO",
    ) -> AuditReceipt:
        digest = context_digest or self.context_digest(
            principal_id, action, resource, request_body
        )
        timestamp = int(time.time())
        response_digest = hashlib.sha256(response_body).digest()
        event = {
            "service": self.service_name,
            "principal_id": principal_id,
            "action": action,
            "resource": resource,
            "context_digest": digest.hex(),
            "response_digest": response_digest.hex(),
            "status": status_code,
            "latency_ms": round(latency_ms, 3),
            "severity": severity,
            "timestamp": timestamp,
            "key_id": self.key_id.hex(),
        }
        connection = self.database.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            entry_hash = self.database.append_audit_log(connection, self.audit_key, event)
            sequence = int(
                connection.execute("SELECT last_insert_rowid()").fetchone()[0]
            )
            signed_payload = canonical_json_object(
                {
                    "service": self.service_name,
                    "sequence": sequence,
                    "entry_hash": entry_hash.hex(),
                    "context_digest": digest.hex(),
                    "response_digest": response_digest.hex(),
                    "status": status_code,
                }
            )
            signature = self.keyring.sign(
                self.key_id,
                signed_payload,
                self.keyring._records[self.key_id].issuer_digest,
            )
            connection.execute(
                "INSERT INTO zkaedi_receipts(sequence, key_id, signature, signed_payload) "
                "VALUES(?, ?, ?, ?)",
                (sequence, self.key_id, signature, signed_payload),
            )
            if idempotency_key is not None:
                cached_value = json.loads(cached_response)
                cached_value["receipt_headers"] = AuditReceipt(
                    signature, sequence, entry_hash, self.key_id
                ).headers()
                cursor = connection.execute(
                    "UPDATE zkaedi_idempotency SET state = 'committed', response = ? "
                    "WHERE idempotency_key = ? AND context_digest = ? AND state = 'pending'",
                    (
                        canonical_json_object(cached_value),
                        idempotency_key,
                        digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise IdempotencyConflict()
            connection.commit()
            return AuditReceipt(signature, sequence, entry_hash, self.key_id)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _replay_response(serialized: bytes) -> Response:
    record = json.loads(serialized)
    headers = list(record["headers"])
    headers.extend(record["receipt_headers"].items())
    body = base64.b64decode(record["body"])
    return Response(
        content=body,
        status_code=record["status_code"],
        headers=dict(headers),
        media_type=record.get("media_type"),
    )


def audited(
    *,
    action: str,
    resource: str,
    severity: str = "INFO",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Sign and audit the result of a function when called inside ZkaediMiddleware."""
    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(function)

        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                context = _request_context.get()
                if context is None:
                    return await function(*args, **kwargs)
                started = time.perf_counter()
                bound = signature.bind_partial(*args, **kwargs)
                resource_value = bound.arguments.get(resource)
                principal_id = context.principal_resolver(context.request)
                digest = context.recorder.context_digest(principal_id, action, resource_value, context.body)
                idem_key = context.request.headers.get("Idempotency-Key")
                try:
                    if idem_key:
                        cached = context.recorder.lookup_idempotency(idem_key, digest)
                        if cached is not None:
                            return _replay_response(cached)
                    result = await function(*args, **kwargs)
                except IdempotencyConflict as exc:
                    raise HTTPException(status_code=409, detail="Idempotency-Key conflict or request in progress") from exc
                except Exception:
                    try:
                        context.recorder.record(
                            principal_id=principal_id, action=action, resource=resource_value,
                            request_body=context.body, status_code="ERROR", response_body=b"",
                            latency_ms=(time.perf_counter() - started) * 1000,
                            context_digest=digest, severity=severity,
                        )
                    finally:
                        context.recorder.discard_idempotency(idem_key)
                    raise
                return execute_result(context, result, principal_id, resource_value, digest, idem_key, started, action, severity)

            return async_wrapper

        @wraps(function)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            context = _request_context.get()
            if context is None:
                return function(*args, **kwargs)
            started = time.perf_counter()
            bound = signature.bind_partial(*args, **kwargs)
            resource_value = bound.arguments.get(resource)
            principal_id = context.principal_resolver(context.request)
            digest = context.recorder.context_digest(principal_id, action, resource_value, context.body)
            idem_key = context.request.headers.get("Idempotency-Key")
            try:
                if idem_key:
                    cached = context.recorder.lookup_idempotency(idem_key, digest)
                    if cached is not None:
                        return _replay_response(cached)
                result = function(*args, **kwargs)
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail="Idempotency-Key conflict or request in progress") from exc
            except Exception:
                try:
                    context.recorder.record(
                        principal_id=principal_id, action=action, resource=resource_value,
                        request_body=context.body, status_code="ERROR", response_body=b"",
                        latency_ms=(time.perf_counter() - started) * 1000,
                        context_digest=digest, severity=severity,
                    )
                finally:
                    context.recorder.discard_idempotency(idem_key)
                raise
            return execute_result(context, result, principal_id, resource_value, digest, idem_key, started, action, severity)

        return async_wrapper if inspect.iscoroutinefunction(function) else sync_wrapper
    return decorate


def execute_result(
    context: _RequestContext,
    result: Any,
    principal_id: str,
    resource_value: Any,
    digest: bytes,
    idem_key: str | None,
    started: float,
    action: str,
    severity: str,
) -> Any:
    try:
        if isinstance(result, Response):
            body = bytes(result.body or b"")
            status_code = result.status_code
            headers = list(result.headers.items())
            media_type = result.media_type
        else:
            response = JSONResponse(content=jsonable_encoder(result))
            body, status_code, headers, media_type = response.body, response.status_code, [], "application/json"
        cache = canonical_json_object(
            {
                "status_code": status_code,
                "headers": headers,
                "media_type": media_type,
                "body": base64.b64encode(body).decode("ascii"),
            }
        )
        context.receipt = context.recorder.record(
            principal_id=principal_id, action=action, resource=resource_value,
            request_body=context.body, status_code=status_code, response_body=body,
            latency_ms=(time.perf_counter() - started) * 1000, context_digest=digest,
            idempotency_key=idem_key, cached_response=cache if idem_key else None, severity=severity,
        )
    except Exception as exc:
        context.recorder.discard_idempotency(idem_key)
        raise HTTPException(status_code=500, detail="Audit receipt could not be committed") from exc
    return result


class ZkaediMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        service_name: str,
        sqlite_path: str | os.PathLike[str],
        audit_key: bytes | str | None = None,
        principal_resolver: Callable[[Any], str] | None = None,
    ) -> None:
        self.app = app
        self.recorder = AuditRecorder(sqlite_path, service_name, audit_key)
        self.principal_resolver = principal_resolver or (
            lambda request: request.headers.get("X-Principal-Id", "anonymous")
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        messages: list[Message] = []
        body_parts: list[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            messages.append(message)
            body_parts.append(message.get("body", b""))
            more_body = message.get("more_body", False)
        raw_body = b"".join(body_parts)
        try:
            body = json.loads(raw_body) if raw_body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = raw_body.decode("utf-8", errors="replace")
        from starlette.requests import Request

        request = Request(scope, receive=receive)
        context = _RequestContext(request, body, self.recorder, self.principal_resolver)
        token = _request_context.set(context)
        index = 0

        async def replay_receive() -> Message:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return await receive()

        async def send_with_receipt(message: Message) -> None:
            if message["type"] == "http.response.start" and context.receipt is not None:
                headers = list(message.get("headers", []))
                headers.extend(
                    (name.lower().encode("ascii"), value.encode("ascii"))
                    for name, value in context.receipt.headers().items()
                )
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, replay_receive, send_with_receipt)
        finally:
            _request_context.reset(token)
