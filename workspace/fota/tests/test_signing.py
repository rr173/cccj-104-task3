"""Acceptance: offline release signing, downgrade resistance, root rotation.

Covers the whole matrix:
* release under the initial root installs end-to-end
* tampered metadata / tampered blocks rejected before critical writes, old
  slot stays bootable, rejection receipt is durable + idempotent
* expired metadata, revoked signers, counter rollback rejected
* offline device traverses several root rotations in one wake-up; a missing
  link or missing old-root authorization fails closed
* interrupted rotation never exposes half-applied trust; retry converges
* concurrent publication with one idempotency key returns one result;
  conflicting content for the same version cannot lower trust state
* after cutover, content signed only by the retired root is rejected
* the pre-existing pause gate still holds over the signed path
"""
import json
import threading
import time
import uuid

import httpx
import pytest

from app import trust as trustlib

from .conftest import h, root_envelope


def _events(client, dev_id):
    return client.get("/api/device/events", headers=h(dev_id)).json()


def _rejections(client, dev_id):
    return [e for e in _events(client, dev_id) if e["event_type"] == "release_rejected"]


def _offer_and_download(d):
    d.register()
    assert d.check_in()["offered"] is True
    d.download()


# --------------------------------------------------------------------------- #
# 1. Happy path under the initial root
# --------------------------------------------------------------------------- #
def test_release_under_initial_root_installs(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    body = d.check_in()
    assert body["offered"] is True
    assert body["trust"]["latest_root_version"] == 1
    assert d._trust is not None and d._trust.root_version == 1

    offer = body["offer"]
    rel = offer["release"]["metadata"]
    assert rel["artifact_sha256"] == img["sha256"]
    assert rel["model"] == "term-x1"
    assert rel["version"] == "2.0.0"
    assert rel["security_counter"] == 1
    assert rel["expires"]

    d.download()
    assert d.install()["result"] == "installed"
    assert d._trust.highest_counter == 1

    # Trust state survives a process restart (new object, same workdir).
    d2 = make_device("d1")
    assert d2._trust.root_version == 1
    assert d2._trust.highest_counter == 1


# --------------------------------------------------------------------------- #
# 2. Tampered metadata rejected before critical writes; slot stays bootable
# --------------------------------------------------------------------------- #
def test_tampered_release_metadata_rejected_before_critical_write(
    client, admin, make_device
):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    _offer_and_download(d)

    # MitM rewrites the display version inside the signed metadata.
    d._offer["release"]["metadata"]["version"] = "9.9.9"
    with pytest.raises(trustlib.TrustError) as e1:
        d.install()
    assert e1.value.reason == "bad_signature"

    # No critical write happened; the old slot is untouched and bootable.
    assert d.active_slot == "A"
    assert d.slots["B"] is None
    assert d.facts["current_version"] == "1.9.0"
    assert not [e for e in _events(client, "d1") if e["event_type"] == "installing"]

    # Durable, queryable receipt on both device and admin views.
    rej = _rejections(client, "d1")
    assert len(rej) == 1
    assert rej[0]["payload"]["reason"] == "bad_signature"
    admin_view = client.get(
        "/api/admin/events", params={"event_type": "release_rejected"}
    ).json()
    assert len(admin_view) == 1

    # Retry is idempotent: same rejection, same receipt, zero new rows.
    with pytest.raises(trustlib.TrustError):
        d.install()
    assert len(_rejections(client, "d1")) == 1


def test_modified_block_rejected_before_critical_writes(
    client, admin, make_device, monkeypatch
):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    d.check_in()

    # The block store serves a tampered chunk 1 (MitM / disk corruption).
    from app import storage

    real_read = storage.read_chunk

    def poisoned(image_sha, index):
        block = real_read(image_sha, index)
        if index == 1 and block is not None:
            return bytes([x ^ 0xFF for x in block])
        return block

    monkeypatch.setattr(storage, "read_chunk", poisoned)

    with pytest.raises(IOError):
        d.download()

    # Old slot preserved, no install attempted.
    assert d.active_slot == "A"
    assert d.slots["B"] is None
    assert d.facts["current_version"] == "1.9.0"
    assert not [e for e in _events(client, "d1") if e["event_type"] == "installing"]

    rej = _rejections(client, "d1")
    assert len(rej) == 1
    assert rej[0]["payload"]["reason"] == "digest_mismatch"

    # Reconnect + retry: still fails closed, receipt deduped.
    with pytest.raises(IOError):
        d.download()
    assert len(_rejections(client, "d1")) == 1


# --------------------------------------------------------------------------- #
# 3. Expired metadata, revoked signers, counter rollback
# --------------------------------------------------------------------------- #
def test_expired_release_rejected(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    _offer_and_download(d)

    # Device clock jumps past the release expiry (31 days > 30-day validity).
    d._clock = time.time() + 31 * 86400
    with pytest.raises(trustlib.TrustError) as e1:
        d.install()
    assert e1.value.reason == "expired"
    assert d.active_slot == "A" and d.slots["B"] is None
    assert _rejections(client, "d1")[0]["payload"]["reason"] == "expired"

    # The service itself refuses to publish already-expired metadata.
    img2, _ = admin.upload_image(version="2.0.1", blob_seed=b"FW-2.0.1", auto_release=False)
    admin.publish_release(img2, expires=trustlib.iso_after(-60), expect=422)


def test_counter_rollback_rejected_and_survives_restart(client, admin, make_device):
    # v2.0.0 with counter 1, then v2.1.0 with counter 5.
    img_a, _ = admin.upload_image(version="2.0.0")          # counter 1
    camp_a = admin.campaign(img_a["id"])
    b_a = admin.batch(camp_a["id"], quota_value=10)
    admin.action(b_a["id"], "activate")

    d = make_device("d1")
    _offer_and_download(d)
    assert d.install()["result"] == "installed"
    assert d._trust.highest_counter == 1
    admin.action(b_a["id"], "complete")

    img_b, _ = admin.upload_image(version="2.0.1", blob_seed=b"FW-2.0.1", counter=5)
    camp_b = admin.campaign(img_b["id"])
    b_b = admin.batch(camp_b["id"], quota_value=10)
    admin.action(b_b["id"], "activate")

    d.check_in()
    d.download()
    assert d.install()["result"] == "installed"
    assert d._trust.highest_counter == 5

    # Process restart: trust store (with the accepted counter) is reloaded.
    d2 = make_device("d1")
    assert d2._trust.highest_counter == 5
    d2.register()  # shadow version 2.0.1 -> the old 2.0.0 release "fits" again

    # Operator (or attacker) re-rolls the stale release in a fresh campaign.
    camp_a2 = admin.campaign(img_a["id"])
    b_a2 = admin.batch(camp_a2["id"], quota_value=10)
    admin.action(b_a2["id"], "activate")

    body = d2.check_in()
    assert body["offered"] is True
    assert body["offer"]["release"]["metadata"]["security_counter"] == 1
    d2.download()
    with pytest.raises(trustlib.TrustError) as e1:
        d2.install()
    assert e1.value.reason == "counter_rollback"
    assert d2.facts["current_version"] == "2.0.1"  # still on the newer build
    assert _rejections(client, "d1")[-1]["payload"]["reason"] == "counter_rollback"

    # The service also refuses to publish a lower counter for the model.
    img_c, _ = admin.upload_image(version="2.0.2", blob_seed=b"FW-2.0.2", auto_release=False)
    admin.publish_release(img_c, counter=3, expect=409)


def test_revoked_signer_rejected(client, admin, make_device):
    admin.ensure_root()
    img, _ = admin.upload_image(version="2.0.0", auto_release=False)
    admin.publish_release(img, sign_priv=admin.kit.rel2_priv)  # signed by rel2
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    # Rotate to root v2 which explicitly revokes the rel2 signing key.
    keys2 = admin.kit.keyset(admin.kit.root2_pub, [admin.kit.rel_pub])
    keys2[trustlib.key_id(admin.kit.rel2_pub)] = trustlib.key_entry(
        admin.kit.rel2_pub, ["release"], revoked=True
    )
    admin.rotate_root(2, keys2, [admin.kit.root_priv, admin.kit.root2_priv])

    d = make_device("d1")
    d.register()
    d.check_in()  # fresh device catches up: chain [v1, v2]
    assert d._trust.root_version == 2
    d.download()
    with pytest.raises(trustlib.TrustError) as e1:
        d.install()
    assert e1.value.reason == "revoked_signer"
    assert d.active_slot == "A" and d.slots["B"] is None
    assert _rejections(client, "d1")[0]["payload"]["reason"] == "revoked_signer"

    # The service refuses new publications from the revoked signer too.
    img2, _ = admin.upload_image(version="2.0.1", blob_seed=b"FW-2.0.1", auto_release=False)
    admin.publish_release(img2, sign_priv=admin.kit.rel2_priv, expect=422)


# --------------------------------------------------------------------------- #
# 4. Root rotation chains
# --------------------------------------------------------------------------- #
def test_offline_device_traverses_multiple_rotations_in_one_wakeup(
    client, admin, make_device
):
    admin.ensure_root()
    d = make_device("d1")
    d.register()
    d.check_in()  # provisions trust v1 (TOFU); nothing offered yet
    assert d._trust.root_version == 1

    # Two rotations happen while the device is offline.
    keys2 = admin.kit.keyset(admin.kit.root2_pub, [admin.kit.rel_pub])
    admin.rotate_root(2, keys2, [admin.kit.root_priv, admin.kit.root2_priv])
    keys3 = admin.kit.keyset(admin.kit.root3_pub, [admin.kit.rel2_pub])
    admin.rotate_root(3, keys3, [admin.kit.root2_priv, admin.kit.root3_priv])

    # Release signed under the newest root's release key.
    img, _ = admin.upload_image(version="2.0.0", auto_release=False)
    admin.publish_release(img, sign_priv=admin.kit.rel2_priv)
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    body = d.check_in()  # one wake-up: chain [v2, v3] arrives
    assert [link["metadata"]["version"] for link in body["trust"]["root_chain"]] == [2, 3]
    assert d._trust.root_version == 3
    d.download()
    assert d.install()["result"] == "installed"

    # Trust state persisted across restart.
    d2 = make_device("d1")
    assert d2._trust.root_version == 3


def test_missing_chain_link_fails_closed(client, admin, make_device):
    admin.ensure_root()
    d = make_device("d1")
    d.register()
    d.check_in()
    assert d._trust.root_version == 1

    kit = admin.kit
    keys2 = kit.keyset(kit.root2_pub, [kit.rel_pub])
    env2 = root_envelope(2, keys2, [kit.root_priv, kit.root2_priv])
    keys3 = kit.keyset(kit.root3_pub, [kit.rel2_pub])
    env3 = root_envelope(3, keys3, [kit.root2_priv, kit.root3_priv])

    # Gap: v2 omitted from the chain.
    with pytest.raises(trustlib.TrustError) as e1:
        d._apply_root_chain([env3])
    assert e1.value.reason == "missing_link"
    assert d._trust.root_version == 1

    # v2 without the OLD root's authorization (only the new root signed).
    env2_no_old = {
        "metadata": env2["metadata"],
        "signatures": [trustlib.sign_envelope(env2["metadata"], kit.root2_priv)],
    }
    with pytest.raises(trustlib.TrustError) as e2:
        d._apply_root_chain([env2_no_old])
    assert e2.value.reason == "bad_signature"
    assert d._trust.root_version == 1

    # The complete, doubly-authorized chain converges.
    d._apply_root_chain([env2, env3])
    assert d._trust.root_version == 3

    # Rejection receipts were recorded for the failed attempts.
    reasons = {e["payload"]["reason"] for e in _rejections(client, "d1")}
    assert {"missing_link", "bad_signature"} <= reasons


def test_rotation_interrupted_retry_converges(client, admin, make_device, monkeypatch):
    admin.ensure_root()
    d = make_device("d1")
    d.register()
    d.check_in()
    assert d._trust.root_version == 1

    keys2 = admin.kit.keyset(admin.kit.root2_pub, [admin.kit.rel_pub])
    admin.rotate_root(2, keys2, [admin.kit.root_priv, admin.kit.root2_priv])
    keys3 = admin.kit.keyset(admin.kit.root3_pub, [admin.kit.rel2_pub])
    admin.rotate_root(3, keys3, [admin.kit.root2_priv, admin.kit.root3_priv])

    # Power loss exactly during the trust-store commit.
    orig_write = d._write_trust_atomic
    calls = {"n": 0}

    def flaky_write(trust):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("power loss mid-rotation")
        return orig_write(trust)

    monkeypatch.setattr(d, "_write_trust_atomic", flaky_write)
    with pytest.raises(RuntimeError):
        d.check_in()

    # No half-applied trust state, in memory or on disk.
    assert d._trust.root_version == 1
    on_disk = json.loads((d.workdir / "trust.json").read_text())
    assert on_disk["root_version"] == 1

    # Retry converges to the newest root and stays there across a restart.
    d.check_in()
    assert d._trust.root_version == 3
    on_disk = json.loads((d.workdir / "trust.json").read_text())
    assert on_disk["root_version"] == 3
    d2 = make_device("d1")
    assert d2._trust.root_version == 3


# --------------------------------------------------------------------------- #
# 5. Publication idempotency / conflicts
# --------------------------------------------------------------------------- #
def test_concurrent_publication_same_idempotency_key_returns_one_result(
    client, admin
):
    admin.ensure_root()
    img, _ = admin.upload_image(version="2.0.0", auto_release=False)
    meta = trustlib.release_metadata(
        model=img["model"],
        version=img["version"],
        artifact_sha256=img["sha256"],
        security_counter=1,
        expires=trustlib.iso_after(86400),
    )
    sigs = [trustlib.sign_envelope(meta, admin.kit.rel_priv)]
    body = {
        "image_id": img["id"],
        "metadata": meta,
        "signatures": sigs,
        "idempotency_key": "pub-" + uuid.uuid4().hex,
    }

    results, errors = [], []
    barrier = threading.Barrier(6)

    def worker():
        try:
            with httpx.Client(transport=client._transport, base_url="http://test") as c:
                barrier.wait(timeout=10)
                results.append(c.post("/api/admin/releases", json=body))
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert all(r.status_code == 200 for r in results)
    assert len({r.json()["id"] for r in results}) == 1
    assert sum(1 for r in results if r.json()["duplicate"] is False) == 1
    assert len(client.get("/api/admin/releases").json()) == 1


def test_conflicting_publication_cannot_lower_trust_state(client, admin):
    admin.ensure_root()
    img, _ = admin.upload_image(version="2.0.0")  # auto release, counter 1

    # Same release version, different content -> conflict.
    meta2 = trustlib.release_metadata(
        model=img["model"],
        version=img["version"],
        artifact_sha256=img["sha256"],
        security_counter=2,
        expires=trustlib.iso_after(86400),
    )
    sigs2 = [trustlib.sign_envelope(meta2, admin.kit.rel_priv)]
    admin.post_release(meta2, sigs2, image_id=img["id"], expect=409)

    # Counter regression on a later version -> conflict.
    img2, _ = admin.upload_image(version="2.0.1", blob_seed=b"FW-2.0.1", auto_release=False)
    admin.publish_release(img2, counter=5, expect=200)
    img3, _ = admin.upload_image(version="2.0.2", blob_seed=b"FW-2.0.2", auto_release=False)
    admin.publish_release(img3, counter=3, expect=409)

    # Root v1 cannot be rewritten; a gap (v3 while at v1) fails closed.
    env1 = root_envelope(
        1, admin.kit.keyset(admin.kit.root_pub, [admin.kit.rel_pub]), [admin.kit.root_priv]
    )
    r = client.post(
        "/api/admin/roots",
        json={**env1, "idempotency_key": "root-rewrite-" + uuid.uuid4().hex},
    )
    assert r.status_code == 409
    env3 = root_envelope(
        3,
        admin.kit.keyset(admin.kit.root3_pub, [admin.kit.rel_pub]),
        [admin.kit.root_priv, admin.kit.root3_priv],
    )
    r = client.post(
        "/api/admin/roots",
        json={**env3, "idempotency_key": "root-gap-" + uuid.uuid4().hex},
    )
    assert r.status_code == 422

    # Idempotency-key replay with identical content returns the stored result;
    # the same key with different content conflicts.
    img4, _ = admin.upload_image(version="2.0.3", blob_seed=b"FW-2.0.3", auto_release=False)
    key = "shared-" + uuid.uuid4().hex
    meta4 = trustlib.release_metadata(
        model=img4["model"],
        version=img4["version"],
        artifact_sha256=img4["sha256"],
        security_counter=6,
        expires=trustlib.iso_after(86400),
    )
    sigs4 = [trustlib.sign_envelope(meta4, admin.kit.rel_priv)]
    r1 = admin.post_release(meta4, sigs4, image_id=img4["id"], idem=key, expect=200)
    r2 = admin.post_release(meta4, sigs4, image_id=img4["id"], idem=key, expect=200)
    assert r1.json()["id"] == r2.json()["id"]
    assert r2.json()["duplicate"] is True
    meta4_evil = dict(meta4, security_counter=7)
    sigs4_evil = [trustlib.sign_envelope(meta4_evil, admin.kit.rel_priv)]
    admin.post_release(meta4_evil, sigs4_evil, image_id=img4["id"], idem=key, expect=409)


# --------------------------------------------------------------------------- #
# 6. Retired root content rejected after cutover
# --------------------------------------------------------------------------- #
def test_retired_root_content_rejected_after_cutover(client, admin, make_device):
    admin.ensure_root()
    img, _ = admin.upload_image(version="2.0.0")  # signed by rel under root v1
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    d.check_in()
    assert d._trust.root_version == 1

    # Cutover: root v2 carries a brand-new release key; the old one is retired.
    keys2 = admin.kit.keyset(admin.kit.root2_pub, [admin.kit.rel2_pub])
    admin.rotate_root(2, keys2, [admin.kit.root_priv, admin.kit.root2_priv])

    d.check_in()  # chain [v2] -> trust v2
    assert d._trust.root_version == 2
    d.download()
    with pytest.raises(trustlib.TrustError) as e1:
        d.install()
    assert e1.value.reason == "bad_signature"  # old release key unknown to v2
    assert d.active_slot == "A" and d.slots["B"] is None

    # Publishing new content signed only by the retired key is refused too.
    img2, _ = admin.upload_image(version="2.0.1", blob_seed=b"FW-2.0.1", auto_release=False)
    admin.publish_release(img2, sign_priv=admin.kit.rel_priv, expect=422)


# --------------------------------------------------------------------------- #
# 7. Pause gate + fail-closed offers over the signed path
# --------------------------------------------------------------------------- #
def test_pause_gate_still_holds_over_signed_path(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    _offer_and_download(d)
    assert d._offer["release"]["metadata"]["artifact_sha256"] == img["sha256"]

    admin.action(b["id"], "pause")
    # Even with a perfectly valid signed release, a paused batch must not let
    # a non-critical device start the critical write phase.
    r = client.post(
        "/api/device/events",
        headers=h("d1"),
        json={
            "assignment_id": d._offer["assignment_id"],
            "event_type": "installing",
            "idempotency_key": "installing-while-paused",
            "payload": {},
        },
    )
    assert r.status_code == 409

    admin.action(b["id"], "resume", force=True)
    d.check_in()
    assert d.install()["result"] == "installed"


def test_unsigned_release_is_never_offered(client, admin):
    img, _ = admin.upload_image(auto_release=False)
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")
    admin.register_device("d1")

    body = client.post("/api/device/check-in", headers=h("d1")).json()
    assert body["offered"] is False
    assert body["reason"] == "no_signed_release"
