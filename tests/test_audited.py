from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import runpy
import sqlite3
import subprocess
import sys
import anyio
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
import pytest
from starlette.responses import JSONResponse, StreamingResponse

from src.audited import AuditRecorder, IdempotencyConflict, ZkaediMiddleware, audited
from src.context_bound_epoch_protocol import AuthorizationDatabase, canonical_json_object
from src.verify_cli import main as verify_main
from src.verify_cli import verify_database


class Refund(BaseModel):
    amount_minor: int


def build_app(db_path: Path, calls: dict[str, int]) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        ZkaediMiddleware,
        service_name="billing-service",
        sqlite_path=str(db_path),
        audit_key=b"a" * 32,
    )

    async def injected_value() -> str:
        return "dependency-ok"

    @app.post("/refund/{account_id}")
    @audited(action="payout.refund", resource="account_id", severity="CRITICAL")
    async def refund(
        account_id: str,
        body: Refund,
        marker: str = Depends(injected_value),
    ):
        calls["refund"] += 1
        return {"account_id": account_id, "amount_minor": body.amount_minor, "marker": marker}

    @app.post("/sync/{account_id}")
    @audited(action="payout.sync", resource="account_id")
    def sync_action(account_id: str):
        calls["sync"] += 1
        return {"account_id": account_id, "status": "ok"}

    @app.post("/sync-failure/{account_id}")
    @audited(action="payout.sync-failure", resource="account_id")
    def sync_failure(account_id: str):
        calls["failure"] += 1
        raise RuntimeError("expected sync failure")

    @app.post("/failure/{account_id}")
    @audited(action="payout.failure", resource="account_id")
    async def failure(account_id: str):
        calls["failure"] += 1
        raise RuntimeError("expected failure")

    @app.post("/accepted/{account_id}")
    @audited(action="payout.accepted", resource="account_id")
    async def accepted(account_id: str):
        return JSONResponse({"account_id": account_id}, status_code=202)

    @app.post("/plain")
    def plain():
        return {"status": "ok"}

    @app.post("/stream/{account_id}")
    @audited(action="payout.stream", resource="account_id")
    async def stream(account_id: str):
        async def chunks():
            yield account_id.encode()
            yield b"-complete"

        return StreamingResponse(chunks(), media_type="text/plain")

    return app


def test_receipt_headers_signature_and_dependency_injection(tmp_path: Path) -> None:
    calls = {"refund": 0, "sync": 0, "failure": 0}
    db_path = tmp_path / "audit.db"
    with TestClient(build_app(db_path, calls)) as client:
        response = client.post(
            "/refund/acct-1",
            json={"amount_minor": 750},
            headers={"X-Principal-Id": "customer-7"},
        )
        assert response.status_code == 200
        assert response.json()["marker"] == "dependency-ok"
        assert response.headers["x-zkaedi-chain-index"] == "1"
        signature = base64.b64decode(response.headers["x-zkaedi-receipt-sig"])
        key_id = bytes.fromhex(response.headers["x-zkaedi-key-id"])
        entry_hash = response.headers["x-zkaedi-entry-hash"]
        connection = sqlite3.connect(db_path)
        try:
            public_key = connection.execute(
                "SELECT public_key FROM key_records WHERE key_id = ?", (key_id,)
            ).fetchone()[0]
            signed_payload = connection.execute(
                "SELECT signed_payload FROM zkaedi_receipts WHERE sequence = 1"
            ).fetchone()[0]
        finally:
            connection.close()
        assert __import__("json").loads(signed_payload)["entry_hash"] == entry_hash
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed_payload)
        connection = sqlite3.connect(db_path)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE audit_events SET payload = ? WHERE sequence = 1", (b"{}",))
        connection.close()
        assert calls["refund"] == 1
        accepted = client.post("/accepted/acct-2")
        assert accepted.status_code == 202
        connection = sqlite3.connect(db_path)
        try:
            payload = json.loads(
                connection.execute(
                    "SELECT payload FROM audit_events WHERE sequence = 2"
                ).fetchone()[0]
            )
        finally:
            connection.close()
        assert payload["status"] == 202
        assert payload["response_digest"] == hashlib.sha256(accepted.content).hexdigest()

    restarted_calls = {"refund": 0, "sync": 0, "failure": 0}
    with TestClient(build_app(db_path, restarted_calls)) as restarted:
        resumed = restarted.post("/sync/acct-3")
        assert resumed.status_code == 200
        assert resumed.headers["x-zkaedi-key-id"] == key_id.hex()
        assert resumed.headers["x-zkaedi-chain-index"] == "3"


def test_idempotent_replay_and_conflicting_payload(tmp_path: Path) -> None:
    calls = {"refund": 0, "sync": 0, "failure": 0}
    with TestClient(build_app(tmp_path / "audit.db", calls)) as client:
        headers = {"Idempotency-Key": "refund-1"}
        first = client.post("/refund/acct-1", json={"amount_minor": 750}, headers=headers)
        replay = client.post("/refund/acct-1", json={"amount_minor": 750}, headers=headers)
        assert replay.status_code == first.status_code == 200
        assert replay.content == first.content
        assert replay.headers["x-zkaedi-receipt-sig"] == first.headers["x-zkaedi-receipt-sig"]
        assert replay.headers["x-zkaedi-chain-index"] == first.headers["x-zkaedi-chain-index"]
        assert calls["refund"] == 1
        conflict = client.post("/refund/acct-1", json={"amount_minor": 751}, headers=headers)
        assert conflict.status_code == 409
        assert calls["refund"] == 1


def test_sync_handler_and_handler_exception_are_audited(tmp_path: Path) -> None:
    calls = {"refund": 0, "sync": 0, "failure": 0}
    db_path = tmp_path / "audit.db"
    with TestClient(build_app(db_path, calls), raise_server_exceptions=False) as client:
        assert client.post("/sync/acct-2").status_code == 200
        failed = client.post("/failure/acct-3")
        sync_failed = client.post("/sync-failure/acct-4")
        assert failed.status_code == 500
        assert sync_failed.status_code == 500
    assert calls["sync"] == 1
    assert calls["failure"] == 2
    connection = sqlite3.connect(db_path)
    try:
        payloads = [row[0] for row in connection.execute("SELECT payload FROM audit_events ORDER BY sequence")]
    finally:
        connection.close()
    assert [json.loads(payload)["status"] for payload in payloads] == [200, "ERROR", "ERROR"]


def test_sync_idempotency_and_unmodified_routes(tmp_path: Path) -> None:
    calls = {"refund": 0, "sync": 0, "failure": 0}
    with TestClient(build_app(tmp_path / "audit.db", calls)) as client:
        headers = {"Idempotency-Key": "sync-1"}
        first = client.post("/sync/acct-2", headers=headers)
        replay = client.post("/sync/acct-2", headers=headers)
        conflict = client.post("/sync/acct-other", headers=headers)
        assert first.content == replay.content
        assert first.headers["x-zkaedi-receipt-sig"] == replay.headers["x-zkaedi-receipt-sig"]
        assert conflict.status_code == 409
        assert client.post("/plain", content=b"\xff").status_code == 200
        streamed = client.post("/stream/acct-stream")
        assert streamed.status_code == 200
        assert streamed.content == b"acct-stream-complete"
        assert calls["sync"] == 1


def test_offline_verifier_detects_tampering(tmp_path: Path) -> None:
    calls = {"refund": 0, "sync": 0, "failure": 0}
    db_path = tmp_path / "audit.db"
    with TestClient(build_app(db_path, calls)) as client:
        response = client.post("/refund/acct-1", json={"amount_minor": 50})
        assert response.status_code == 200
    environment = {**os.environ, "ZKAEDI_AUDIT_KEY": (b"a" * 32).hex()}
    command = [sys.executable, "-m", "src.verify_cli", str(db_path)]
    verified = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert verified.returncode == 0
    assert "PASS:" in verified.stdout
    valid, count, receipt_count, _ = verify_database(str(db_path), b"a" * 32)
    assert (valid, count, receipt_count) == (True, 1, 1)
    valid, _, _, _ = verify_database(str(db_path), b"a" * 32, "0" * 64)
    assert not valid
    valid, _, _, _ = verify_database(str(db_path), b"a" * 32, "nope")
    assert not valid

    with patch.dict(os.environ, {"ZKAEDI_AUDIT_KEY": (b"a" * 32).hex()}):
        assert verify_main([str(db_path)]) == 0
    with patch.dict(os.environ, {}, clear=True):
        assert verify_main([str(db_path)]) == 1
    with patch.dict(os.environ, {"ZKAEDI_AUDIT_KEY": "not-hex"}):
        assert verify_main([str(db_path)]) == 1
    with patch.dict(os.environ, {"ZKAEDI_AUDIT_KEY": "00"}):
        assert verify_main([str(db_path)]) == 1
    with patch.dict(os.environ, {"ZKAEDI_AUDIT_KEY": (b"a" * 32).hex()}):
        with patch.object(sys, "argv", ["verify_cli", str(db_path)]):
            try:
                runpy.run_path(str(Path(__file__).parents[1] / "src" / "verify_cli.py"), run_name="__main__")
            except SystemExit as exc:
                assert exc.code == 0
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("DROP TRIGGER IF EXISTS audit_events_update_guard")
        connection.execute("UPDATE audit_events SET payload = ? WHERE sequence = 1", (b"{}",))
        connection.commit()
    finally:
        connection.close()
    tampered = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert tampered.returncode == 1
    assert "FAIL:" in tampered.stdout


def test_framework_agnostic_audit_recorder(tmp_path: Path) -> None:
    recorder = AuditRecorder(tmp_path / "direct.db", "worker", b"b" * 32)
    receipt = recorder.record(
        principal_id="batch-user",
        action="batch.run",
        resource="job-7",
        request_body={"job": 7},
        status_code=200,
        response_body=b'{"status":"ok"}',
        latency_ms=2.5,
    )
    assert receipt.sequence == 1
    assert len(receipt.signature) == 64


def test_audit_commit_failure_fails_closed(tmp_path: Path, monkeypatch) -> None:
    calls = {"refund": 0, "sync": 0, "failure": 0}

    def fail_record(*_args, **_kwargs):
        raise RuntimeError("storage unavailable")

    def fail_discard(*_args, **_kwargs):
        raise RuntimeError("cleanup unavailable")

    monkeypatch.setattr(AuditRecorder, "record", fail_record)
    monkeypatch.setattr(AuditRecorder, "discard_idempotency", fail_discard)
    with TestClient(
        build_app(tmp_path / "fail-closed.db", calls), raise_server_exceptions=False
    ) as client:
        response = client.post(
            "/refund/acct-fail", json={"amount_minor": 2},
            headers={"Idempotency-Key": "fail-closed"},
        )
    assert response.status_code == 500
    assert "x-zkaedi-receipt-sig" not in response.headers
    assert calls["refund"] == 1


def test_middleware_non_http_and_receive_replay(tmp_path: Path) -> None:
    calls: list[str] = []

    async def app(scope, receive, send):
        calls.append(scope["type"])
        if scope["type"] == "http":
            assert (await receive())["body"] == b"request"
            assert (await receive())["type"] == "http.disconnect"
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

    middleware = ZkaediMiddleware(
        app, service_name="test", sqlite_path=str(tmp_path / "asgi.db"), audit_key=b"f" * 32
    )
    sent: list[dict] = []
    message_index = 0

    async def receive():
        nonlocal message_index
        if message_index == 0:
            message_index += 1
            return {"type": "http.request", "body": b"request", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    async def invoke() -> None:
        nonlocal message_index
        await middleware({"type": "lifespan"}, receive, send)
        calls.clear()
        message_index = 0
        await middleware(
            {"type": "http", "headers": [], "method": "POST", "path": "/"},
            receive,
            send,
        )

    anyio.run(invoke, backend="asyncio")
    assert calls == ["http"]
    assert sent[-1]["type"] == "http.response.body"


def test_audit_recorder_validation_key_recovery_and_idempotency(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "recorder.db"
    with pytest.raises(ValueError):
        AuditRecorder(path, "", b"x" * 32)
    monkeypatch.delenv("ZKAEDI_AUDIT_KEY", raising=False)
    with pytest.raises(ValueError):
        AuditRecorder(path, "worker")
    with pytest.raises(ValueError):
        AuditRecorder(path, "worker", "not-hex")
    with pytest.raises(ValueError):
        AuditRecorder(path, "worker", b"x" * 31)

    recorder = AuditRecorder(path, "worker", b"c" * 32)
    original_key = recorder.key_id
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE zkaedi_receipt_private_keys SET encrypted_seed = ? WHERE key_id = ?",
        (b"tampered", original_key),
    )
    connection.commit()
    connection.close()
    recovered = AuditRecorder(path, "worker", b"c" * 32)
    assert recovered.key_id != original_key

    context_digest = recovered.context_digest("actor", "do", "resource", {"v": 1})
    assert recovered.lookup_idempotency("idem", context_digest) is None
    with pytest.raises(IdempotencyConflict):
        recovered.lookup_idempotency("idem", context_digest)
    recovered.discard_idempotency(None)
    recovered.discard_idempotency("idem")

    assert recovered.lookup_idempotency("idem", context_digest) is None
    cache = canonical_json_object(
        {
            "status_code": 200,
            "headers": [],
            "media_type": "application/json",
            "body": "e30=",
        }
    )
    recovered.record(
        principal_id="actor",
        action="do",
        resource="resource",
        request_body={"v": 1},
        status_code=200,
        response_body=b"{}",
        latency_ms=1,
        context_digest=context_digest,
        idempotency_key="idem",
        cached_response=cache,
    )
    assert recovered.lookup_idempotency("idem", context_digest) is not None
    with pytest.raises(IdempotencyConflict):
        recovered.lookup_idempotency("idem", b"d" * 32)
    with pytest.raises(IdempotencyConflict):
        recovered.record(
            principal_id="actor",
            action="do",
            resource="resource",
            request_body={"v": 1},
            status_code=200,
            response_body=b"{}",
            latency_ms=1,
            context_digest=context_digest,
            idempotency_key="not-reserved",
            cached_response=cache,
        )


def test_audit_recorder_sql_failures_and_verifier_legacy_schema(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "failures.db"
    recorder = AuditRecorder(path, "worker", b"d" * 32)
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TRIGGER reject_idempotency BEFORE INSERT ON zkaedi_idempotency "
        "BEGIN SELECT RAISE(ABORT, 'no inserts'); END"
    )
    connection.execute(
        "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'no audit'); END"
    )
    connection.commit()
    connection.close()
    with pytest.raises(IdempotencyConflict):
        recorder.lookup_idempotency("blocked", b"x" * 32)
    with pytest.raises(sqlite3.IntegrityError):
        recorder.record(
            principal_id="actor",
            action="do",
            resource=None,
            request_body={},
            status_code=200,
            response_body=b"",
            latency_ms=1,
        )

    class FailedConnection:
        in_transaction = True
        rolled_back = False

        def execute(self, *_args):
            raise RuntimeError("database unavailable")

        def rollback(self):
            self.rolled_back = True

        def close(self):
            pass

    failed_connection = FailedConnection()
    monkeypatch.setattr(recorder.database, "connect", lambda: failed_connection)
    with pytest.raises(RuntimeError):
        recorder.lookup_idempotency("failed", b"x" * 32)
    assert failed_connection.rolled_back

    legacy_path = tmp_path / "legacy.db"
    database = AuthorizationDatabase(legacy_path)
    connection = database.connect()
    database.append_audit_log(connection, b"e" * 32, {"legacy": True})
    connection.close()
    valid, count, receipt_count, _ = verify_database(str(legacy_path), b"e" * 32)
    assert (valid, count, receipt_count) == (True, 1, 0)


def test_verifier_rejects_malformed_chain_receipts_and_schema(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "verify-failures.db"
    audit_key = b"g" * 32
    recorder = AuditRecorder(path, "verifier", audit_key)
    receipt = recorder.record(
        principal_id="actor",
        action="verify",
        resource="item",
        request_body={},
        status_code=200,
        response_body=b"{}",
        latency_ms=1,
    )
    connection = sqlite3.connect(path)
    event = connection.execute(
        "SELECT previous_hash, event_hash, payload FROM audit_events WHERE sequence = 1"
    ).fetchone()
    key_row = connection.execute(
        "SELECT key_id, public_key, purpose, issuer_digest, status FROM key_records WHERE key_id = ?",
        (receipt.key_id,),
    ).fetchone()
    signed_row = connection.execute(
        "SELECT key_id, signature, signed_payload FROM zkaedi_receipts WHERE sequence = 1"
    ).fetchone()
    connection.execute("DROP TRIGGER audit_events_update_guard")
    connection.execute("DROP TRIGGER key_records_delete_guard")
    connection.commit()
    connection.close()

    connection = sqlite3.connect(path)
    connection.execute("UPDATE audit_events SET sequence = 2 WHERE sequence = 1")
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key)[0]
    connection = sqlite3.connect(path)
    connection.execute("UPDATE audit_events SET sequence = 1 WHERE sequence = 2")
    connection.execute("UPDATE audit_events SET event_hash = ? WHERE sequence = 1", (b"x" * 32,))
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key)[0]

    malformed = b"not-json"
    malformed_hash = hmac.digest(audit_key, event[0] + malformed, hashlib.sha256)
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE audit_events SET event_hash = ?, payload = ? WHERE sequence = 1",
        (malformed_hash, malformed),
    )
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key)[0]
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE audit_events SET event_hash = ?, payload = ? WHERE sequence = 1",
        (event[1], event[2]),
    )
    connection.execute("DELETE FROM zkaedi_receipts WHERE sequence = 1")
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key)[0]

    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO zkaedi_receipts(sequence, key_id, signature, signed_payload) VALUES(1, ?, ?, ?)",
        signed_row,
    )
    connection.execute("DELETE FROM key_records WHERE key_id = ?", (receipt.key_id,))
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key)[0]

    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO key_records(key_id, public_key, purpose, issuer_digest, status) VALUES(?, ?, ?, ?, ?)",
        key_row,
    )
    connection.execute("UPDATE zkaedi_receipts SET signed_payload = ? WHERE sequence = 1", (b"{}",))
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key)[0]
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE zkaedi_receipts SET signature = ?, signed_payload = ? WHERE sequence = 1",
        (bytes([signed_row[1][0] ^ 1]) + signed_row[1][1:], signed_row[2]),
    )
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key)[0]
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE zkaedi_receipts SET signature = ? WHERE sequence = 1",
        (signed_row[1],),
    )
    connection.commit()
    connection.close()
    assert not verify_database(str(path), audit_key, "g" * 64)[0]

    invalid_schema = tmp_path / "invalid-schema.db"
    sqlite3.connect(invalid_schema).close()
    assert not verify_database(str(invalid_schema), audit_key)[0]

    class CloseFailure:
        close_count = 0

        def execute(self, *_args):
            raise sqlite3.OperationalError("no schema")

        def close(self):
            self.close_count += 1
            if self.close_count == 2:
                raise sqlite3.OperationalError("close failed")

    close_failure = CloseFailure()
    monkeypatch.setattr("src.verify_cli.sqlite3.connect", lambda *_args, **_kwargs: close_failure)
    assert not verify_database(str(path), audit_key)[0]


def test_decorator_without_middleware_is_transparent() -> None:
    @audited(action="direct.async", resource="name")
    async def async_operation(name: str) -> str:
        return name

    @audited(action="direct.sync", resource="name")
    def sync_operation(name: str) -> str:
        return name

    async def invoke() -> None:
        assert await async_operation("async") == "async"

    anyio.run(invoke, backend="asyncio")
    assert sync_operation("sync") == "sync"
