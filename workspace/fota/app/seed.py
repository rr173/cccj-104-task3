"""Idempotent demo seed: one signed release + canary batch for HW2026Q3."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, publishing, storage
from . import trust as trustlib
from .models import BATCH_PENDING, Batch, Campaign, Image

DEMO_MODEL = os.environ.get("DEMO_MODEL", "term-x1")
DEMO_VERSION = os.environ.get("DEMO_VERSION", "2.0.0")
DEMO_HW = os.environ.get("DEMO_HW", "HW2026Q3")

# Demo keys live next to the DB so restarts keep the same trust root. In a real
# deployment the root/release private keys stay OFFLINE (HSM/KMS); this file
# exists only so the compose demo can rotate/publish more content by hand.
DEMO_KEYS_PATH = Path(
    os.environ.get("DEMO_KEYS_PATH", str(Path(config.STORAGE_ROOT).parent / "demo_keys.json"))
)


def _demo_firmware() -> bytes:
    # Deterministic pseudo-firmware (~600 KiB, ~3 chunks at 256 KiB blocks).
    size = 600_000
    pattern = bytes((i * 31 + 7) % 256 for i in range(256))
    reps = size // len(pattern) + 1
    return (pattern * reps)[:size]


def _demo_keys() -> dict:
    if DEMO_KEYS_PATH.exists():
        return json.loads(DEMO_KEYS_PATH.read_text())
    keys = {}
    for name in ("root", "release"):
        priv, pub = trustlib.generate_keypair()
        keys[name] = {"private": priv, "public": pub}
    DEMO_KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEMO_KEYS_PATH.write_text(json.dumps(keys, indent=2))
    return keys


def seed_if_empty(db: Session) -> None:
    if db.scalar(select(Image).where(Image.model == DEMO_MODEL)):
        return
    keys = _demo_keys()

    # Trust root v1 (self-signed bootstrap) — idempotent across restarts.
    if publishing.current_root(db) is None:
        root_meta = trustlib.root_metadata(
            1,
            {
                trustlib.key_id(keys["root"]["public"]): trustlib.key_entry(
                    keys["root"]["public"], ["root"]
                ),
                trustlib.key_id(keys["release"]["public"]): trustlib.key_entry(
                    keys["release"]["public"], ["release"]
                ),
            },
            trustlib.iso_after(180 * 86400),
        )
        publishing.publish_root(
            db,
            metadata=root_meta,
            signatures=[trustlib.sign_envelope(root_meta, keys["root"]["private"])],
            idempotency_key="seed-root-v1",
        )

    stored = storage.save_blob(_demo_firmware())
    img = Image(
        id=str(uuid.uuid4()),
        model=DEMO_MODEL,
        version=DEMO_VERSION,
        min_bootloader="1.0.0",
        max_bootloader="1.99.0",
        size=stored.size,
        sha256=stored.sha256,
        chunk_size=stored.chunk_size,
        chunk_count=stored.chunk_count,
    )
    db.add(img)
    db.flush()
    camp = Campaign(id=str(uuid.uuid4()), name=f"demo-{DEMO_MODEL}-{DEMO_VERSION}", image_id=img.id)
    db.add(camp)
    db.flush()
    canary = Batch(
        id=str(uuid.uuid4()),
        campaign_id=camp.id,
        hardware_batch=DEMO_HW,
        stage=1,
        quota_mode="absolute",
        quota_value=2,
        failure_threshold=0.5,
        failure_min_sample=3,
        parent_id=None,
        state=BATCH_PENDING,
    )
    db.add(canary)

    # Signed release bound to the demo image (counter 1, +180d expiry).
    rel_meta = trustlib.release_metadata(
        model=DEMO_MODEL,
        version=DEMO_VERSION,
        artifact_sha256=stored.sha256,
        security_counter=1,
        expires=trustlib.iso_after(180 * 86400),
    )
    publishing.publish_release(
        db,
        image_id=img.id,
        metadata=rel_meta,
        signatures=[trustlib.sign_envelope(rel_meta, keys["release"]["private"])],
        idempotency_key="seed-release-" + stored.sha256[:16],
    )
    db.commit()
