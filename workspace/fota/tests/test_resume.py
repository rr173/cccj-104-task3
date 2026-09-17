"""Verified-block resume across intermittent connectivity."""
import hashlib


def test_interrupted_download_resumes_from_verified_blocks(client, admin, make_device):
    img, blob = admin.upload_image(size=200)  # 4 chunks of 64 bytes
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=1)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    assert d.check_in()["offered"] is True

    # First connection dies after two new blocks; two are persisted.
    try:
        d.download(fail_after_chunks=2)
        assert False, "expected simulated disconnect"
    except ConnectionError:
        pass

    partial = (d.workdir / f"{img['sha256']}.bin").read_bytes()
    assert partial[:128] == blob[:128]
    assert partial[128:] == b"\x00" * 72

    # Reconnect: resume, only remaining blocks fetched.
    out = d.download()
    assert out["aborted"] is None
    assert out["new_blocks"] == 2
    assert out["verified_blocks"] == 4

    full = (d.workdir / f"{img['sha256']}.bin").read_bytes()
    assert hashlib.sha256(full).hexdigest() == img["sha256"]

    # The downloaded receipt lands once and install can proceed.
    res = d.install()
    assert res["result"] == "installed"
    assert d.facts["current_version"] == "2.0.0"


def test_corrupt_local_block_is_refetched(client, admin, make_device):
    img, blob = admin.upload_image(size=200)
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=1)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    d.check_in()
    try:
        d.download(fail_after_chunks=3)
    except ConnectionError:
        pass

    # Corrupt block 1 "on disk" (power loss garbage).
    path = d.workdir / f"{img['sha256']}.bin"
    raw = bytearray(path.read_bytes())
    raw[10] ^= 0xFF
    path.write_bytes(bytes(raw))

    out = d.download()
    assert out["new_blocks"] == 2  # corrupted block 1 + missing block 3
    d.install()


def test_repeated_resume_after_many_disconnects(client, admin, make_device):
    img, _ = admin.upload_image(size=200)
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=1)
    admin.action(b["id"], "activate")

    d = make_device("d1")
    d.register()
    d.check_in()
    for n in (1, 1, 1):
        try:
            d.download(fail_after_chunks=n)
        except ConnectionError:
            d.check_in()
    out = d.download()
    assert out["verified_blocks"] == 4
    d.install()
