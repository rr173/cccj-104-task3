"""Real HTTP process (not TestClient) end-to-end for the notarization layer.

Spawns an actual uvicorn worker against an on-disk SQLite DB + storage dir,
drives it over HTTP, kills the process hard (SIGKILL), and starts a SECOND
worker against the SAME files. Proves:

* the quarantine and ledger state are real durable on-disk state, not in-process
  caches — after restart the model is still refused and the log head is intact;
* a first registration yields a verifiable membership witness over the wire.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from app import notary as notarylib
from app import trust as trustlib

ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_ready(base: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(base + "/healthz", timeout=1.0)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.15)
    raise RuntimeError("service did not become ready")


@pytest.fixture()
def live_service(tmp_path):
    db = tmp_path / "live.db"
    storage = tmp_path / "artifacts"
    keys = tmp_path / "notary_keys.json"
    port = _free_port()
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite:///{db}",
        "STORAGE_ROOT": str(storage),
        "NOTARY_KEYS_PATH": str(keys),
        "CHUNK_SIZE": "64",
        "SEED_DEMO": "false",
        "PYTHONPATH": str(ROOT),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_ready(base)
        yield base, {"db": db, "storage": storage, "keys": keys}
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGKILL)
            proc.wait(timeout=10)


def _bootstrap_signed_release(base: str) -> tuple[dict, dict]:
    kit_priv, kit_pub = trustlib.generate_keypair()
    rel_priv, rel_pub = trustlib.generate_keypair()
    keys = {trustlib.key_id(kit_pub): trustlib.key_entry(kit_pub, ["root"]),
            trustlib.key_id(rel_pub): trustlib.key_entry(rel_pub, ["release"])}
    root_meta = trustlib.root_metadata(1, keys, trustlib.iso_after(30 * 86400))
    r = httpx.post(base + "/api/admin/roots", json={
        "metadata": root_meta,
        "signatures": [trustlib.sign_envelope(root_meta, kit_priv)],
        "idempotency_key": "real-root-v1",
    }, timeout=10)
    assert r.status_code == 200, r.text

    blob = bytes((i * 13 + 5) % 256 for i in range(200))
    r = httpx.post(base + "/api/admin/images", timeout=10,
                   files={"file": ("fw.bin", blob, "application/octet-stream")},
                   data={"model": "term-x1", "version": "2.0.0",
                         "min_bootloader": "1.0.0", "max_bootloader": "1.99.0"})
    assert r.status_code == 201, r.text
    img = r.json()
    rel_meta = trustlib.release_metadata(
        model="term-x1", version="2.0.0", artifact_sha256=img["sha256"],
        security_counter=1, expires=trustlib.iso_after(30 * 86400))
    r = httpx.post(base + "/api/admin/releases", json={
        "image_id": img["id"], "metadata": rel_meta,
        "signatures": [trustlib.sign_envelope(rel_meta, rel_priv)],
        "idempotency_key": "real-rel-1",
    }, timeout=10)
    assert r.status_code == 200, r.text
    return img, {"root_priv": kit_priv, "root_pub": kit_pub}


def test_quarantine_and_log_survive_real_process_restart(live_service):
    base, paths = live_service
    img, _ = _bootstrap_signed_release(base)

    r = httpx.post(base + "/api/admin/campaigns",
                   json={"name": "real", "image_id": img["id"]}, timeout=10)
    camp = r.json()
    r = httpx.post(base + "/api/admin/batches", json={
        "campaign_id": camp["id"], "hardware_batch": "HW1", "stage": 1,
        "quota_mode": "absolute", "quota_value": 10,
        "failure_threshold": 0.5, "failure_min_sample": 2}, timeout=10)
    batch = r.json()
    assert httpx.post(base + f"/api/admin/batches/{batch['id']}/action",
                      json={"action": "activate"}, timeout=10).status_code == 200

    # Membership witness over real HTTP.
    httpx.post(base + "/api/device/register", json={
        "id": "realdev", "model": "term-x1", "hardware_batch": "HW1",
        "bootloader": "1.2.0", "current_version": "1.9.0"}, timeout=10)
    ci = httpx.post(base + "/api/device/check-in",
                    headers={"X-Device-Id": "realdev"}, timeout=10).json()
    assert ci["offered"] is True
    w = ci["offer"]["notary"]
    notarylib.verify_checkpoint_signature(w["checkpoint"], w["public"])
    notarylib.verify_inclusion(
        index=w["leaf"]["index"], size=w["checkpoint"]["tree_size"],
        leaf=notarylib.entry_leaf_hash(w["leaf"]["entry"]),
        proof=[bytes.fromhex(x) for x in w["inclusion"]],
        root=bytes.fromhex(w["checkpoint"]["root"]))
    size = w["checkpoint"]["tree_size"]
    canonical_root = w["checkpoint"]["root"]

    # Equivocation using the on-disk notary key (the key holder misbehaves).
    keys = json.loads(Path(paths["keys"]).read_text())
    alt_cp = notarylib.sign_checkpoint(
        tree_size=size, root="ab" * 32,
        time=trustlib.iso_after(0), priv_hex=keys["private"])
    r = httpx.post(base + "/api/admin/notary/checkpoints/alternate",
                   json={"checkpoint": alt_cp}, timeout=10)
    assert r.status_code == 200
    assert "term-x1" in r.json()["quarantined_models"]

    # New claim already blocked in process 1.
    httpx.post(base + "/api/device/register", json={
        "id": "realdev2", "model": "term-x1", "hardware_batch": "HW1",
        "bootloader": "1.2.0", "current_version": "1.9.0"}, timeout=10)
    ci = httpx.post(base + "/api/device/check-in",
                    headers={"X-Device-Id": "realdev2"}, timeout=10).json()
    assert ci["reason"] == "model_quarantined"

    # SIGKILL the process and start a NEW one on the same DB + key file.
    port = _free_port()
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite:///{paths['db']}",
        "STORAGE_ROOT": str(paths["storage"]),
        "NOTARY_KEYS_PATH": str(paths["keys"]),
        "CHUNK_SIZE": "64",
        "SEED_DEMO": "false",
        "PYTHONPATH": str(ROOT),
    }
    proc2 = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(ROOT), env=env)
    base2 = f"http://127.0.0.1:{port}"
    try:
        _wait_ready(base2)
        q = httpx.get(base2 + "/api/admin/notary/quarantine", timeout=10).json()
        assert [row["model"] for row in q] == ["term-x1"]
        head = httpx.get(base2 + "/api/admin/notary/checkpoint", timeout=10).json()
        assert head["tree_size"] == size
        assert head["root"] == canonical_root  # alternate never replaced it
        ci = httpx.post(base2 + "/api/device/check-in",
                        headers={"X-Device-Id": "realdev2"}, timeout=10).json()
        assert ci["reason"] == "model_quarantined"
    finally:
        proc2.send_signal(signal.SIGKILL)
        proc2.wait(timeout=10)
