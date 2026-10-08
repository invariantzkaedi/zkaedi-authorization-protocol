"""End-to-End Quickstart & Tamper-Evident Demonstration for ZKAEDI.

This script executes four sequential steps:
1. Starts a FastAPI application equipped with ZkaediMiddleware and an @audited mutation endpoint.
2. Executes an audited payout mutation, verifying the emission of Ed25519 action receipt headers.
3. Runs the offline verifier CLI with zero environment variables and zero secrets, confirming integrity.
4. Simulates a rogue database administrator bypassing SQLite triggers and tampering with a row payload,
   then runs the zero-secret offline verifier again to demonstrate deterministic failure.
"""

import os
import sys
import sqlite3
import subprocess
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from src.audited import audited, ZkaediMiddleware

DB_PATH = "demo_audit_vault.db"
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)


class RefundPayload(BaseModel):
    amount_minor: int
    reason: str


app = FastAPI(title="ZKAEDI Demo App")
app.add_middleware(
    ZkaediMiddleware,
    service_name="billing-service",
    sqlite_path=DB_PATH,
    key_encryption_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
)


@app.post("/api/v1/payouts/{account_id}/refund")
@audited(action="payout.refund", resource="account_id", severity="CRITICAL")
async def refund_customer(account_id: str, payload: RefundPayload):
    return {"status": "processed", "account_id": account_id, "refunded": payload.amount_minor}


def main():
    print("=" * 70)
    print("ZKAEDI END-TO-END DEMO: FASTAPI MUTATION -> RECEIPT -> TAMPER PROOF")
    print("=" * 70)

    print("\n[Step 1] Executing audited POST mutation via FastAPI...")
    with TestClient(app) as client:
        res = client.post(
            "/api/v1/payouts/acct_prod_99/refund",
            json={"amount_minor": 14500, "reason": "chargeback_resolution"},
        )
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        print(f"Status Code: {res.status_code}")
        print(f"Response:    {res.json()}")
        print("Emitted Action Receipt Headers:")
        for h in [
            "x-zkaedi-chain-index",
            "x-zkaedi-entry-hash",
            "x-zkaedi-key-id",
            "x-zkaedi-receipt-sig",
        ]:
            print(f"  {h}: {res.headers.get(h)}")

    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("ZKAEDI_")}

    print("\n[Step 2] Verifying offline with ZERO secrets (no ZKAEDI_* env vars)...")
    proc = subprocess.run(
        [sys.executable, "-m", "src.verify_cli", DB_PATH],
        env=clean_env,
        capture_output=True,
        text=True,
    )
    print(f"Exit Code: {proc.returncode}")
    print(proc.stdout.strip())
    assert proc.returncode == 0, "Initial verification must pass"

    print("\n[Step 3] Simulating Rogue DBA directly updating SQLite table...")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TRIGGER IF EXISTS audit_events_update_guard")
    conn.execute("UPDATE audit_events SET payload = ? WHERE sequence = 1", (b'{"tampered": true}',))
    conn.commit()
    conn.close()
    print("Database payload modified behind the application's back.")

    print("\n[Step 4] Running offline verifier on tampered database...")
    proc_tampered = subprocess.run(
        [sys.executable, "-m", "src.verify_cli", DB_PATH],
        env=clean_env,
        capture_output=True,
        text=True,
    )
    print(f"Exit Code: {proc_tampered.returncode}")
    print(proc_tampered.stdout.strip())
    assert proc_tampered.returncode == 1, "Verification must fail on tampered records"

    print("\n" + "=" * 70)
    print("VERIFICATION SUCCEEDED: Tampering was detected deterministically with ZERO secrets.")
    print("=" * 70)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


if __name__ == "__main__":
    main()
