"""Pause / halt safety:

* not-yet-installed devices stop (no chunks, no check-in offer)
* devices already in the critical region (installing) must still be allowed to
  finish or roll back (safe wind-down)
* halting cascades through staged descendants
* resuming a halted batch needs explicit force
"""
from .conftest import h


def _offer(client, dev_id):
    return client.post("/api/device/check-in", headers=h(dev_id)).json()


def test_pause_blocks_not_yet_installed_devices(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    assert d.check_in()["offered"] is True
    d.download()  # now "downloaded", not yet installing

    r = admin.action(b["id"], "pause")
    assert r.status_code == 200

    body = d.check_in()
    assert body["offered"] is False
    assert body["reason"] == "batch_paused"

    # Chunk gate refuses too (defense in depth even though client stops itself).
    r = client.get(
        f"/api/device/artifacts/{img['id']}/chunks/0",
        params={"assignment_id": d._offer["assignment_id"]},
        headers=h("d1"),
    )
    assert r.status_code == 409

    # Starting install is refused while paused.
    r = client.post(
        "/api/device/events",
        headers=h("d1"),
        json={
            "assignment_id": d._offer["assignment_id"],
            "event_type": "installing",
            "idempotency_key": "installing-attempt-1",
            "payload": {},
        },
    )
    assert r.status_code == 409


def test_pause_lets_critical_region_device_finish(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    d.check_in()
    d.download()
    d._event("installing", {"slot": "B"})  # flash writes have started

    # Operator pauses mid-flash: the device wakes, and MUST get an offer so it
    # can finish and confirm — never stranded with a half-written critical area.
    admin.action(b["id"], "pause")
    body = d.check_in()
    assert body["offered"] is True
    assert body["offer"]["finalize_only"] is True

    # Chunk path remains open for the critical-region device.
    r = client.get(
        f"/api/device/artifacts/{img['id']}/chunks/0",
        params={"assignment_id": d._offer["assignment_id"]},
        headers=h("d1"),
    )
    assert r.status_code == 200

    # ...device finishes writing, health-checks the new slot and confirms.
    r = client.post(
        "/api/device/events",
        headers=h("d1"),
        json={
            "assignment_id": d._offer["assignment_id"],
            "event_type": "installed",
            "idempotency_key": "installed-1",
            "payload": {"version": "2.0.0", "slot": "B"},
        },
    )
    assert r.status_code == 200
    assert client.get("/api/admin/devices").json()[0]["current_version"] == "2.0.0"


def test_halt_cascades_to_descendant_stages(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b1 = admin.batch(camp["id"], stage=1, quota_value=10)
    b2 = admin.batch(camp["id"], stage=2, quota_value=10, parent_id=b1["id"])
    b3 = admin.batch(camp["id"], stage=3, quota_value=10, parent_id=b2["id"])
    for b in (b1, b2, b3):
        assert admin.action(b["id"], "activate").status_code == 200

    admin.action(b1["id"], "halt")
    for b in (b1, b2, b3):
        assert client.get(f"/api/admin/batches/{b['id']}").json()["state"] == "halted"

    admin.register_device("d1")
    body = _offer(client, "d1")
    assert body["offered"] is False
    assert body["reason"] in ("batch_halted", "no_campaign")


def test_halt_lets_critical_region_device_finish_or_rollback(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1", fail_install=True)
    d.register()
    d.check_in()
    d.download()
    d._event("installing", {"slot": "B"})  # critical region entered

    # Kill switch after flash writes began: the device still gets the manifest
    # and is allowed to report failure + rollback completion (safe wind-down).
    admin.action(b["id"], "halt")
    assert d.check_in()["offer"]["finalize_only"] is True

    # Health check of the new slot fails: it boots the old slot and reports the
    # tail of the FSM; both receipts must be accepted while the batch is halted.
    res = d._event("failed", {"reason": "post-flash health check failed: sim",
                              "rolled_back_to": "1.9.0"})
    assert res["to_state"] == "failed"
    d._event("rollback_complete", {"rolled_back_to": "1.9.0", "slot": "A"})

    asg = client.get(f"/api/admin/assignments?batch_id={b['id']}").json()[0]
    assert asg["install_state"] == "failed"
    assert "health check failed" in asg["fail_reason"]
    assert client.get("/api/admin/devices").json()[0]["current_version"] == "1.9.0"


def test_resume_halted_requires_force(client, admin):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")
    admin.action(b["id"], "halt")

    r = admin.action(b["id"], "resume")
    assert r.status_code == 409
    r = admin.action(b["id"], "resume", force=True)
    assert r.status_code == 200
    assert r.json()["state"] == "active"


def test_paused_mid_download_device_holds_then_resumes(client, admin, make_device):
    img, _ = admin.upload_image(size=200)
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    d.check_in()
    try:
        d.download(fail_after_chunks=1)
    except ConnectionError:
        pass

    # Pause while still downloading: device reconnects, is told to stop.
    admin.action(b["id"], "pause")
    body = d.check_in()
    assert body["offered"] is False
    # Chunk gate refuses mid-download fetch.
    r = client.get(
        f"/api/device/artifacts/{img['id']}/chunks/1",
        params={"assignment_id": d._offer["assignment_id"]},
        headers=h("d1"),
    )
    assert r.status_code == 409

    # Resume later -> resume from verified blocks and finish.
    admin.action(b["id"], "resume", force=True)
    d.check_in()
    out = d.download()
    assert out["verified_blocks"] == 4
    d.install()
