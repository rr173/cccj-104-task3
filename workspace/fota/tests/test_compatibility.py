"""Compatibility: model / bootloader window / current version gating."""
from .conftest import h


def _offer(client, dev_id):
    r = client.post("/api/device/check-in", headers=h(dev_id))
    assert r.status_code == 200
    return r.json()


def test_model_mismatch_gets_no_offer(client, admin):
    img, _ = admin.upload_image(model="term-x1", version="2.0.0")
    camp = admin.campaign(img["id"])
    admin.batch(camp["id"], hardware_batch="HW1", quota_value=10)
    admin.register_device("d1", model="term-x2")
    body = _offer(client, "d1")
    assert body["offered"] is False
    assert body["reason"] == "no_campaign"


def test_bootloader_window(client, admin):
    img, _ = admin.upload_image(
        model="term-x1", version="2.0.0", min_bootloader="1.1.0", max_bootloader="1.5.0"
    )
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")

    admin.register_device("old", bootloader="1.0.9")
    admin.register_device("ok", bootloader="1.2.0")
    admin.register_device("new", bootloader="1.5.1")

    assert _offer(client, "old")["reason"] == "no_campaign"
    assert _offer(client, "ok")["offered"] is True
    assert _offer(client, "new")["reason"] == "no_campaign"


def test_already_on_target_version_not_offered(client, admin):
    img, _ = admin.upload_image(version="2.0.0")
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")
    admin.register_device("uptodate", current_version="2.0.0")
    body = _offer(client, "uptodate")
    assert body["offered"] is False
    assert body["reason"] == "no_campaign"


def test_offer_contains_block_manifest(client, admin):
    img, blob = admin.upload_image(version="2.0.0", size=200)  # 200/64 = 4 chunks
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")
    admin.register_device("d1")
    offer = _offer(client, "d1")["offer"]
    assert offer["version"] == "2.0.0"
    assert offer["chunk_size"] == 64
    assert offer["chunks"][-1]["size"] == 200 - 3 * 64
    assert sum(c["size"] for c in offer["chunks"]) == 200
    assert offer["finalize_only"] is False
