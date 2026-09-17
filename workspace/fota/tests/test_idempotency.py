"""Idempotency: duplicate check-ins and replays must be side-effect free."""

from .conftest import h


def test_duplicate_receipt_is_replayed_without_side_effects(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10, failure_min_sample=100)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    d.check_in()
    d.download()
    asg_id = d._offer["assignment_id"]

    payload_inst = {
        "assignment_id": asg_id,
        "event_type": "installing",
        "idempotency_key": "installing-key-001",
        "payload": {"slot": "B"},
    }
    payload = {
        "assignment_id": asg_id,
        "event_type": "installed",
        "idempotency_key": "install-key-001",
        "payload": {"version": "2.0.0", "slot": "B"},
    }
    assert client.post("/api/device/events", headers=h("d1"), json=payload_inst).status_code == 200
    r1 = client.post("/api/device/events", headers=h("d1"), json=payload)
    r2 = client.post("/api/device/events", headers=h("d1"), json=payload)
    r3 = client.post("/api/device/events", headers=h("d1"), json=payload)
    assert r1.json()["duplicate"] is False
    assert {r2.json()["duplicate"], r3.json()["duplicate"]} == {True}
    assert r2.json()["to_state"] == "installed"

    # Exactly one state-moving event row; the terminal installed device still
    # holds exactly one seat.
    events = client.get("/api/admin/events", headers=h("d1")).json()
    state_events = [e for e in events if e["event_type"] == "installed"]
    assert len(state_events) == 1

    stats = client.get(f"/api/admin/batches/{b['id']}").json()["stats"]
    assert stats["seats"] == 1
    assert stats["installed"] == 1


def test_concurrent_duplicate_checkins_claim_one_seat(client, admin):
    """Real HTTP concurrency: N simultaneous check-ins from one device (flaky
    radio fired the request N times) must create one assignment."""
    import threading

    import httpx

    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")
    admin.register_device("dup")

    transport = client._transport
    results: list = []
    errors: list = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            with httpx.Client(transport=transport, base_url="http://test") as c:
                barrier.wait(timeout=10)
                r = c.post("/api/device/check-in", headers=h("dup"))
                results.append(r.json())
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(results) == 8
    assert all(r["offered"] for r in results)
    assignment_ids = {r["offer"]["assignment_id"] for r in results}
    assert len(assignment_ids) == 1

    stats = client.get(f"/api/admin/batches/{b['id']}").json()["stats"]
    assert stats["seats"] == 1


def test_quota_race_between_distinct_devices(client, admin):
    """8 distinct devices racing for 3 seats: exactly 3 win, no overshoot."""
    import threading

    import httpx

    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=3)
    admin.action(b["id"], "activate")
    for i in range(8):
        admin.register_device(f"d{i}")

    transport = client._transport
    results: list = []
    errors: list = []
    barrier = threading.Barrier(8)

    def worker(i):
        try:
            with httpx.Client(transport=transport, base_url="http://test") as c:
                barrier.wait(timeout=10)
                r = c.post("/api/device/check-in", headers=h(f"d{i}"))
                results.append(r.json())
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert sum(1 for r in results if r["offered"]) == 3
    stats = client.get(f"/api/admin/batches/{b['id']}").json()["stats"]
    assert stats["seats"] == 3


def test_backward_transition_is_rejected(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10, failure_min_sample=100)
    admin.action(b["id"], "activate")

    d = make_device("d1", fail_install=True)
    d.register(); d.check_in()
    d.download(); d.install()  # -> failed (terminal)

    # A delayed/duplicate "downloaded" receipt arriving after failure is illegal.
    r = client.post(
        "/api/device/events",
        headers=h("d1"),
        json={
            "assignment_id": d._offer["assignment_id"],
            "event_type": "downloaded",
            "idempotency_key": "stale-late-key",
            "payload": {},
        },
    )
    assert r.status_code == 409

    # Unknown event types are 400.
    r = client.post(
        "/api/device/events",
        headers=h("d1"),
        json={
            "assignment_id": d._offer["assignment_id"],
            "event_type": "nonsense",
            "idempotency_key": "nonsense-key",
            "payload": {},
        },
    )
    assert r.status_code == 400


def test_telemetry_duplicates_are_safe(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")
    d = make_device("d1")
    d.register(); d.check_in()
    d.download()
    # download_started fired with its own stable key; re-running download (e.g.
    # after a reconnect with everything already verified) replays it harmlessly.
    d.download()
    events = client.get("/api/device/events", headers=h("d1")).json()
    assert sum(1 for e in events if e["event_type"] == "download_started") == 1
