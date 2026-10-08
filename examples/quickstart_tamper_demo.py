"""End-to-End Quickstart & Tamper-Evident Demonstration for ZKAEDI.

This script executes four sequential steps:
1. Starts a FastAPI application equipped with ZkaediMiddleware, an @audited mutation endpoint,
   and an out-of-band JSONL checkpoint sink for external log aggregation.
2. Executes an audited payout mutation, verifying the emission of Ed25519 action receipt headers
   and export of out-of-band pinned public keys.
3. Runs the offline verifier CLI with zero secrets and pinned trusted keys, confirming integrity.
4. Simulates a rogue database administrator bypassing SQLite triggers and tampering with records,
   then runs the offline verifier again to demonstrate deterministic failure.
"""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from zkaedi import audited, file_checkpoint_sink, ZkaediMiddleware

DB_PATH = "demo_audit_vault.db"
CHECKPOINT_PATH = "demo_checkpoints.jsonl"
PINNED_KEYS_PATH = "demo_pinned_keys.json"

for path in [DB_PATH, CHECKPOINT_PATH, PINNED_KEYS_PATH]:
    if os.path.exists(path):
        os.remove(path)


class RefundPayload(BaseModel):
    amount_minor: int
    reason: str


app = FastAPI(title="ZKAEDI Demo App")
middleware = ZkaediMiddleware(
    app,
    service_name="billing-service",
    sqlite_path=DB_PATH,
    key_encryption_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    checkpoint_sink=file_checkpoint_sink(CHECKPOINT_PATH),
)
app.add_middleware(
    ZkaediMiddleware,
    service_name="billing-service",
    sqlite_path=DB_PATH,
    key_encryption_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    checkpoint_sink=file_checkpoint_sink(CHECKPOINT_PATH),
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

    # Verify checkpoint left the box into external JSONL sink
    assert os.path.exists(CHECKPOINT_PATH)
    checkpoint_line = Path(CHECKPOINT_PATH).read_text(encoding="utf-8").strip()
    checkpoint = json.loads(checkpoint_line)
    print(f"\n[Checkpoint Sink] Out-of-band checkpoint streamed to {CHECKPOINT_PATH}:")
    print(f"  Sequence: {checkpoint['sequence']}, Chain Head: {checkpoint['chain_head'][:16]}...")

    # Export authorized public keys for out-of-band pinning
    recorder = middleware.recorder
    pinned_keys = recorder.export_public_keys()
    Path(PINNED_KEYS_PATH).write_text(json.dumps(pinned_keys, indent=2), encoding="utf-8")
    print(f"[Trust Anchor] Pinned {len(pinned_keys)} authorized signing key(s) to {PINNED_KEYS_PATH}")

    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("ZKAEDI_")}

    print("\n[Step 2] Verifying offline with ZERO secrets and pinned trusted keys...")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "zkaedi.verify_cli",
            DB_PATH,
            "--trusted-keys",
            PINNED_KEYS_PATH,
            "--checkpoint",
            checkpoint["chain_head"],
        ],
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
        [
            sys.executable,
            "-m",
            "zkaedi.verify_cli",
            DB_PATH,
            "--trusted-keys",
            PINNED_KEYS_PATH,
        ],
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

    for path in [DB_PATH, CHECKPOINT_PATH, PINNED_KEYS_PATH]:
        if os.path.exists(path):
            os.remove(path)


if __name__ == "__main__":
    main()
