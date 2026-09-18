"""Test harness: isolated temp DB + artifact root, small blocks, fresh app."""
from __future__ import annotations

import io
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

# Configure env BEFORE importing app.config (settings are read at import time).
_TMP = Path(tempfile.mkdtemp(prefix="fota-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'test.db'}"
os.environ["STORAGE_ROOT"] = str(_TMP / "artifacts")
os.environ["CHUNK_SIZE"] = "64"          # tiny blocks -> many chunks in tests
os.environ["FAILURE_THRESHOLD"] = "0.5"
os.environ["FAILURE_MIN_SAMPLE"] = "2"
os.environ["SEED_DEMO"] = "false"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import trust as trustlib  # noqa: E402
from client import SimDevice  # noqa: E402


@pytest.fixture()
def client():
    # Drop/recreate schema for full isolation per test.
    from app import db as dbmod
    from app.db import Base, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    dbmod.config.STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    from app.main import app

    with TestClient(app) as c:
        yield c


def _blob(seed: bytes, size: int = 200) -> bytes:
    out = bytearray()
    while len(out) < size:
        out.extend(seed)
    return bytes(out[:size])


# --------------------------------------------------------------------------- #
# Offline signing kit — private keys never touch the service DB
# --------------------------------------------------------------------------- #
class TrustKit:
    """Key material for tests: two root keys (rotations), two release keys
    (revocation). The service only ever sees the public halves inside signed
    metadata, exactly like a real offline signer."""

    def __init__(self):
        self.root_priv, self.root_pub = trustlib.generate_keypair()
        self.root2_priv, self.root2_pub = trustlib.generate_keypair()
        self.root3_priv, self.root3_pub = trustlib.generate_keypair()
        self.rel_priv, self.rel_pub = trustlib.generate_keypair()
        self.rel2_priv, self.rel2_pub = trustlib.generate_keypair()

    def keyset(self, root_pub, release_pubs, revoked=()):
        keys = {trustlib.key_id(root_pub): trustlib.key_entry(root_pub, ["root"])}
        for p in release_pubs:
            keys[trustlib.key_id(p)] = trustlib.key_entry(
                p, ["release"], revoked=p in revoked
            )
        return keys


def root_envelope(version, keys, sign_with, expires=None):
    """Build a signed root-metadata envelope entirely offline."""
    meta = trustlib.root_metadata(version, keys, expires or trustlib.iso_after(30 * 86400))
    return {
        "metadata": meta,
        "signatures": [trustlib.sign_envelope(meta, p) for p in sign_with],
    }


class AdminHelper:
    def __init__(self, client):
        self.c = client
        self.kit: TrustKit | None = None
        self._counters: dict[str, int] = {}

    # ----- trust root -----
    def ensure_root(self) -> TrustKit:
        """Bootstrap root v1 (self-signed) once per test."""
        if self.kit is None:
            self.kit = TrustKit()
            env = root_envelope(
                1,
                self.kit.keyset(self.kit.root_pub, [self.kit.rel_pub, self.kit.rel2_pub]),
                [self.kit.root_priv],
            )
            r = self.c.post(
                "/api/admin/roots",
                json={**env, "idempotency_key": f"root-v1-{uuid.uuid4().hex[:12]}"},
            )
            assert r.status_code == 200, r.text
        return self.kit

    def rotate_root(self, version, keys, sign_with, *, expires=None, expect=200):
        env = root_envelope(version, keys, sign_with, expires)
        r = self.c.post(
            "/api/admin/roots",
            json={**env, "idempotency_key": f"root-v{version}-{uuid.uuid4().hex[:12]}"},
        )
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    # ----- releases -----
    def post_release(self, meta, sigs, *, image_id=None, idem=None, expect=200):
        r = self.c.post(
            "/api/admin/releases",
            json={
                "image_id": image_id,
                "metadata": meta,
                "signatures": sigs,
                "idempotency_key": idem or f"rel-{uuid.uuid4().hex}",
            },
        )
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    def publish_release(
        self, img, *, counter=None, expires=None, sign_priv=None, idem=None, expect=200
    ):
        self.ensure_root()
        model = img["model"]
        if counter is None:
            counter = self._counters.get(model, 0) + 1
        self._counters[model] = max(self._counters.get(model, 0), counter)
        meta = trustlib.release_metadata(
            model=model,
            version=img["version"],
            artifact_sha256=img["sha256"],
            security_counter=counter,
            expires=expires or trustlib.iso_after(30 * 86400),
        )
        sigs = [trustlib.sign_envelope(meta, sign_priv or self.kit.rel_priv)]
        return self.post_release(meta, sigs, image_id=img["id"], idem=idem, expect=expect)

    # ----- images / campaigns / batches -----
    def upload_image(
        self,
        *,
        model="term-x1",
        version="2.0.0",
        min_bootloader="1.0.0",
        max_bootloader="1.99.0",
        blob_seed=b"FW-2.0",
        size=200,
        auto_release=True,
        counter=None,
    ):
        blob = _blob(blob_seed, size)
        r = self.c.post(
            "/api/admin/images",
            data={
                "model": model,
                "version": version,
                "min_bootloader": min_bootloader,
                "max_bootloader": max_bootloader,
            },
            files={"file": ("fw.bin", io.BytesIO(blob), "application/octet-stream")},
        )
        assert r.status_code == 201, r.text
        img = r.json()
        if auto_release:
            self.publish_release(img, counter=counter)
        return img, blob

    def campaign(self, image_id, name=None):
        r = self.c.post(
            "/api/admin/campaigns",
            json={"name": name or f"c-{uuid.uuid4().hex[:8]}", "image_id": image_id},
        )
        assert r.status_code == 201, r.text
        return r.json()

    def batch(
        self,
        campaign_id,
        *,
        hardware_batch="HW1",
        stage=1,
        quota_mode="absolute",
        quota_value=10,
        failure_threshold=0.5,
        failure_min_sample=2,
        parent_id=None,
    ):
        r = self.c.post(
            "/api/admin/batches",
            json={
                "campaign_id": campaign_id,
                "hardware_batch": hardware_batch,
                "stage": stage,
                "quota_mode": quota_mode,
                "quota_value": quota_value,
                "failure_threshold": failure_threshold,
                "failure_min_sample": failure_min_sample,
                "parent_id": parent_id,
            },
        )
        assert r.status_code == 201, r.text
        return r.json()

    def action(self, batch_id, action, force=False):
        return self.c.post(
            f"/api/admin/batches/{batch_id}/action",
            json={"action": action, "force": force},
        )

    def register_device(
        self,
        dev_id,
        *,
        model="term-x1",
        hardware_batch="HW1",
        bootloader="1.2.0",
        current_version="1.9.0",
    ):
        r = self.c.post(
            "/api/admin/devices",
            json={
                "id": dev_id,
                "model": model,
                "hardware_batch": hardware_batch,
                "bootloader": bootloader,
                "current_version": current_version,
            },
        )
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture()
def admin(client):
    return AdminHelper(client)


@pytest.fixture()
def make_device(client, tmp_path):
    """Factory producing a SimDevice bound to the TestClient transport."""

    def _make(dev_id, **kw):
        c = httpx.Client(transport=client._transport, base_url="http://test")
        d = SimDevice.__new__(SimDevice)  # build without spawning a second client
        d.client = c
        d.device_id = dev_id
        d.facts = {
            "id": dev_id,
            "model": kw.get("model", "term-x1"),
            "hardware_batch": kw.get("hardware_batch", "HW1"),
            "bootloader": kw.get("bootloader", "1.2.0"),
            "current_version": kw.get("current_version", "1.9.0"),
        }
        d.workdir = tmp_path / dev_id
        d.workdir.mkdir(parents=True, exist_ok=True)
        d.fail_install = kw.get("fail_install", False)
        d.slots = {"A": d.facts["current_version"], "B": None}
        d.active_slot = "A"
        d._offer = None
        d._clock = kw.get("clock")  # tests may pin/advance the device clock
        d._trust = None
        d._notary = None
        d._idem = d._load_idem()
        d._load_persisted_state()
        return d

    return _make


def h(dev_id):
    return {"X-Device-Id": dev_id}
