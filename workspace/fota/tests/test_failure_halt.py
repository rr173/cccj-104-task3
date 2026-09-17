"""Failure-rate threshold stops diffusion automatically and cascades."""
from .conftest import h


def _finish_ok(d):
    d.download()
    return d.install()


def _finish_fail(d):
    d.download()
    return d.install()  # fail_install=True -> failed + rollback receipt


def test_threshold_cross_halts_batch_and_children(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    # threshold 0.5, min sample 2: >=50% over 2 attempts trips it
    b1 = admin.batch(camp["id"], stage=1, quota_value=10,
                     failure_threshold=0.5, failure_min_sample=2)
    b2 = admin.batch(camp["id"], stage=2, quota_value=10, parent_id=b1["id"])
    admin.action(b1["id"], "activate")
    admin.action(b2["id"], "activate")

    d1 = make_device("d1", fail_install=True)
    d1.register()
    d1.check_in()
    res = _finish_fail(d1)
    assert res["result"] == "failed"
    # 1/1 = 100% but min_sample=2 -> not yet
    assert client.get(f"/api/admin/batches/{b1['id']}").json()["state"] == "active"
    # rollback updated device shadow back to previous bootable version
    dev = next(x for x in client.get("/api/admin/devices").json() if x["id"] == "d1")
    assert dev["current_version"] == "1.9.0"

    d2 = make_device("d2", fail_install=True)
    d2.register()
    d2.check_in()
    res = _finish_fail(d2)
    # 2/2 = 100% >= 50% -> batch halted, descendant stage halted too
    assert set(res["halted"]) == {b1["id"], b2["id"]}
    assert client.get(f"/api/admin/batches/{b1['id']}").json()["state"] == "halted"
    assert client.get(f"/api/admin/batches/{b2['id']}").json()["state"] == "halted"

    # New devices no longer diffuse.
    admin.register_device("d3")
    body = client.post("/api/device/check-in", headers=h("d3")).json()
    assert body["offered"] is False
    assert body["reason"] in ("batch_halted", "no_campaign")

    stats = client.get(f"/api/admin/batches/{b1['id']}").json()["stats"]
    assert stats["failed"] == 2
    assert stats["failure_rate"] == 1.0


def test_below_threshold_keeps_rollout_alive(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10,
                    failure_threshold=0.5, failure_min_sample=3)
    admin.action(b["id"], "activate")

    bad = make_device("bad", fail_install=True)
    bad.register(); bad.check_in(); _finish_fail(bad)
    for dev_id in ("g1", "g2"):
        d = make_device(dev_id)
        d.register(); d.check_in(); _finish_ok(d)

    full = client.get(f"/api/admin/batches/{b['id']}").json()
    assert full["state"] == "active"
    assert full["stats"]["failure_rate"] == 1 / 3  # strictly below 0.5


def test_threshold_is_inclusive(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10,
                    failure_threshold=0.5, failure_min_sample=2)
    admin.action(b["id"], "activate")
    for dev_id, fail in (("a", True), ("b", False)):
        d = make_device(dev_id, fail_install=fail)
        d.register(); d.check_in()
        d.download(); d.install()
    # >= threshold trips
    assert client.get(f"/api/admin/batches/{b['id']}").json()["state"] == "halted"


def test_fail_reason_is_recorded(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10, failure_min_sample=100)
    admin.action(b["id"], "activate")
    d = make_device("d1", fail_install=True)
    d.register(); d.check_in()
    d.download(); d.install()
    asg = client.get(f"/api/admin/assignments?batch_id={b['id']}").json()[0]
    assert "health check failed" in asg["fail_reason"]
    assert asg["install_state"] == "failed"
