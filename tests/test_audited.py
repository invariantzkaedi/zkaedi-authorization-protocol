from __future__ import annotations

import base64
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from src.audited import ZkaediMiddleware, audited


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

    @app.post("/failure/{account_id}")
    @audited(action="payout.failure", resource="account_id")
    async def failure(account_id: str):
        calls["failure"] += 1
        raise RuntimeError("expected failure")

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
        assert calls["refund"] == 1


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
        assert failed.status_code == 500
    assert calls["sync"] == calls["failure"] == 1
    connection = sqlite3.connect(db_path)
    try:
        payloads = [row[0] for row in connection.execute("SELECT payload FROM audit_events ORDER BY sequence")]
    finally:
        connection.close()
    assert [__import__("json").loads(payload)["status"] for payload in payloads] == [200, "ERROR"]


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

