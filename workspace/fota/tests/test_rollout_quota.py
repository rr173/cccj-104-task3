"""Staged rollout: quota seats, percentage quotas, failed seats don't churn."""
from .conftest import h


def _offer(client, dev_id):
    return client.post("/api/device/check-in", headers=h(dev_id)).json()


def test_absolute_quota_is_hard_cap(client, admin):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=3)
    admin.action(b["id"], "activate")
    for i in range(5):
        admin.register_device(f"d{i}")

    offered = [_offer(client, f"d{i}")["offered"] for i in range(5)]
    assert offered.count(True) == 3
    assert offered.count(False) == 2

    stats = client.get(f"/api/admin/batches/{b['id']}").json()["stats"]
    assert stats["seats"] == 3


def test_repeated_checkin_does_not_consume_extra_seats(client, admin):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=2)
    admin.action(b["id"], "activate")
    admin.register_device("d1")

    for _ in range(5):
        body = _offer(client, "d1")
        assert body["offered"] is True
        assert body["offer"]["assignment_id"] == body["offer"]["assignment_id"]

    stats = client.get(f"/api/admin/batches/{b['id']}").json()["stats"]
    assert stats["seats"] == 1


def test_percent_quota_against_fleet_size(client, admin):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_mode="percent", quota_value=40)
    admin.action(b["id"], "activate")
    for i in range(10):
        admin.register_device(f"d{i}")

    offered = [_offer(client, f"d{i}")["offered"] for i in range(10)]
    assert offered.count(True) == 4  # floor(10*40/100)


def test_staged_batches_follow_stage_order(client, admin):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b1 = admin.batch(camp["id"], hardware_batch="HW1", stage=1, quota_value=1)
    b2 = admin.batch(
        camp["id"], hardware_batch="HW1", stage=2, quota_value=10, parent_id=b1["id"]
    )
    admin.action(b1["id"], "activate")
    admin.action(b2["id"], "activate")
    for i in range(3):
        admin.register_device(f"d{i}")

    # stage 1 cap=1, even though stage 2 is also active devices hit stage 1 first
    offered = [_offer(client, f"d{i}") for i in range(3)]
    seats_stage1 = client.get(f"/api/admin/batches/{b1['id']}").json()["stats"]["seats"]
    seats_stage2 = client.get(f"/api/admin/batches/{b2['id']}").json()["stats"]["seats"]
    assert seats_stage1 == 1
    assert seats_stage2 == 2
    assert all(o["offered"] for o in offered)


def test_failed_devices_keep_their_seat(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=1, failure_min_sample=100)  # don't auto-halt
    admin.action(b["id"], "activate")

    flaky = make_device("flaky", fail_install=True)
    flaky.register()
    assert flaky.check_in()["offered"] is True
    flaky.download()
    res = flaky.install()
    assert res["result"] == "failed"

    # A new device must NOT take the freed-looking seat: quota is still full.
    admin.register_device("other")
    body = _offer(client, "other")
    assert body["offered"] is False
    assert body["reason"] == "quota_full"

    stats = client.get(f"/api/admin/batches/{b['id']}").json()["stats"]
    assert stats["seats"] == 1
    assert stats["failed"] == 1
