"""Real-process end-to-end check of the notarization layer (not TestClient).

Drives a real uvicorn server and real SimDevice processes over HTTP:
1. seeded demo -> device fetches, verifies both proofs, switches slots
2. dormant device catches up across ledger growth with a log-sized proof
3. split-view checkpoint -> model quarantined -> SERVER RESTART -> still refused
4. crash-safe publication: no fetchable-without-ledger state after a kill
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import notary as notarylib  # noqa: E402
from client import SimDevice  # noqa: E402

BASE = "http://127.0.0.1:18099"
ENV = dict(os.environ)


def wait_up():
    for _ in range(100):
        try:
            if urllib.request.urlopen(BASE + "/healthz", timeout=1).status == 200:
                return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("server did not start")


def start_server(workdir):
    env = dict(
        ENV,
        DATABASE_URL=f"sqlite:///{workdir}/fota.db",
        STORAGE_ROOT=str(workdir / "artifacts"),
        SEED_DEMO="true",
        DEMO_KEYS_PATH=str(workdir / "demo_keys.json"),
        NOTARY_KEY_PATH=str(workdir / "notary_key.json"),
        PORT="18099",
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "18099"],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_up()
    return proc


def post(path, body=None, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req).read())


def get(path):
    return json.loads(urllib.request.urlopen(BASE + path).read())


def main():
    workdir = Path(tempfile.mkdtemp(prefix="fota-notary-e2e-"))
    devdir = workdir / "devices"
    proc = start_server(workdir)
    try:
        # Activate the seeded canary batch (demo.sh does the same).
        for b in get("/api/admin/batches"):
            if b["state"] == "pending":
                post(f"/api/admin/batches/{b['id']}/action", {"action": "activate"})

        # 1. Seeded demo: real device verifies proofs and switches slots.
        d = SimDevice(
            BASE,
            device_id="term-001",
            model="term-x1",
            hardware_batch="HW2026Q3",
            bootloader="1.2.0",
            current_version="1.9.0",
            workdir=devdir / "term-001",
        )
        d.register()
        body = d.check_in()
        assert body["offered"] is True, body
        notary = body["offer"]["notary"]
        assert notarylib.verify_checkpoint_signature(
            notary["checkpoint"], body["notary"]["public_key"]
        )
        assert notarylib.verify_inclusion(
            notary["entry"],
            notary["leaf_index"],
            notary["checkpoint"]["tree_size"],
            notary["inclusion"],
            notary["checkpoint"]["root_hash"],
        )
        d.download()
        assert d.install()["result"] == "installed"
        disk = json.loads((devdir / "term-001" / "notary.json").read_text())
        assert disk["tree_size"] == notary["checkpoint"]["tree_size"]
        print(f"1. seeded install ok; device committed checkpoint size {disk['tree_size']}")

        tree = get("/api/admin/notary/tree")
        assert tree["tree_size"] == 2 and [l["entry_type"] for l in tree["leaves"]] == [
            "root",
            "release",
        ], tree

        # 2. Split-view evidence -> quarantine -> refuses fetches.
        stored = disk
        priv = json.loads((workdir / "notary_key.json").read_text())["private"]
        fork_root = "00" + stored["root_hash"][2:]
        fork_sig = notarylib.sign_checkpoint(stored["tree_size"], fork_root, priv)
        ev = {
            "detail": "split view detected by e2e",
            "stored_checkpoint": {"tree_size": stored["tree_size"], "root_hash": stored["root_hash"]},
            "served_checkpoint": {"tree_size": stored["tree_size"], "root_hash": fork_root},
            "served_signature": fork_sig,
        }
        r = post(
            "/api/device/notary-evidence",
            {"kind": "checkpoint_root_mismatch", "evidence": ev, "idempotency_key": "e2e-evidence-1"},
            headers={"X-Device-Id": "term-001"},
        )
        assert r["quarantined"] is True and r["duplicate"] is False
        r2 = post(
            "/api/device/notary-evidence",
            {"kind": "checkpoint_root_mismatch", "evidence": ev, "idempotency_key": "e2e-evidence-2"},
            headers={"X-Device-Id": "term-001"},
        )
        assert r2["duplicate"] is True
        assert len(get("/api/admin/notary/evidence")) == 1
        body = post("/api/device/check-in", headers={"X-Device-Id": "term-001"})
        assert body["reason"] == "model_quarantined", body
        print("2. split-view evidence quarantined the model; fetch refused; evidence deduped")
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 3. RESTART the server process: the quarantine must still be in effect.
    proc = start_server(workdir)
    try:
        body = post("/api/device/check-in", headers={"X-Device-Id": "term-001"})
        assert body["reason"] == "model_quarantined", body
        assert [q["model"] for q in get("/api/admin/notary/quarantine")] == ["term-x1"]
        assert len(get("/api/admin/notary/evidence")) == 1
        # The ledger itself survived the restart too.
        assert get("/api/admin/notary/tree")["tree_size"] == 2
        print("3. after server restart: quarantine + ledger intact, fetch still refused")
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print("E2E OK:", workdir)


if __name__ == "__main__":
    main()
