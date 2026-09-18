"""Acceptance: supply-chain notarization (append-only Merkle ledger).

Covers the whole matrix:
* Merkle math self-checks: every inclusion/consistency proof round-trips for
  trees of size 1..64, and any tampering is detected
* first registration returns a verifiable membership proof; the device
  verifies both proofs and completes the slot switch
* a long-dormant device catches up across many growths with ONE log-sized
  consistency proof (never the full history)
* flipped membership bytes / dropped history linkage / a smaller tree all
  close the path BEFORE any disk write, the active slot stays bootable, and
  repeated reports of the same material stay a single evidence row
* two validly-signed same-size checkpoints with different roots (split view)
  quarantine the model — and the quarantine survives a service restart
* a kill between the artifact record and the leaf commit leaves no orphan
  and no double leaf; the retried request yields exactly one of each
* six concurrent publications sharing one request token produce one business
  object and grow the tree exactly once
* when the quarantine lands, a device already flashing may finish and report,
  a device that has not touched disk is stopped
"""
import json
import math
import threading
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app import notary as notarylib
from app import trust as trustlib
from app.config import NOTARY_KEY_PATH

from .conftest import h


# --------------------------------------------------------------------------- #
# MitM transport: rewrites check-in responses (a compromised network/notary)
# --------------------------------------------------------------------------- #
class Mitm(httpx.BaseTransport):
    def __init__(self, inner, rewrite):
        self._inner = inner
        self._rewrite = rewrite

    def handle_request(self, request):
        resp = self._inner.handle_request(request)
        if request.method == "POST" and request.url.path == "/api/device/check-in":
            resp.read()
            body = json.loads(resp.content.decode())
            new = self._rewrite(body)
            if new is not None:
                data = json.dumps(new).encode()
                headers = dict(resp.headers)
                headers["content-length"] = str(len(data))
                return httpx.Response(
                    resp.status_code, headers=headers, content=data, request=request
                )
        return resp


def _mitm_device(d, client, rewrite):
    """Re-point a SimDevice at a response-rewriting transport."""
    d.client = httpx.Client(
        transport=Mitm(client._transport, rewrite), base_url="http://test"
    )
    return d


def _notary_private_key():
    """The test plays a compromised notary: it signs with the real key."""
    return json.loads(NOTARY_KEY_PATH.read_text())["private"]


def _flip(hexstr: str) -> str:
    return hexstr[:-1] + ("0" if hexstr[-1] != "0" else "1")


def _evidence(client, model=None):
    params = {"model": model} if model else {}
    return client.get("/api/admin/notary/evidence", params=params).json()


def _quarantine(client):
    return client.get("/api/admin/notary/quarantine").json()


def _tree(client):
    return client.get("/api/admin/notary/tree").json()


def _offer_campaign(admin, img, quota=5):
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=quota)
    admin.action(b["id"], "activate")
    return b


# --------------------------------------------------------------------------- #
# 0. Merkle math: proofs round-trip; any tamper is caught
# --------------------------------------------------------------------------- #
def test_merkle_proofs_roundtrip_and_tamper_detection():
    for n in range(1, 65):
        entries = [{"entry": "release", "i": i, "n": n} for i in range(n)]
        leaves = [notarylib.leaf_hash(e) for e in entries]
        root = notarylib.mth(leaves)

        # Inclusion: every leaf verifies; flipped path / wrong index fails.
        for i in (0, n // 2, n - 1):
            path = notarylib.inclusion_path(leaves, i)
            assert notarylib.verify_inclusion(entries[i], i, n, path, root)
            if path:
                bad = list(path)
                bad[-1] = _flip(bad[-1])
                assert not notarylib.verify_inclusion(entries[i], i, n, bad, root)
            assert not notarylib.verify_inclusion(entries[i], i, n, path, _flip(root))
            wrong = {"entry": "release", "i": i, "n": n, "forged": True}
            assert not notarylib.verify_inclusion(wrong, i, n, path, root)

        # Consistency: every prefix connects; tampered proofs fail.
        for m in {1, n // 2, n - 1}:
            if not 1 <= m < n:
                continue
            proof = notarylib.consistency_proof(leaves, m)
            assert proof  # a real growth always carries a non-empty proof
            assert len(proof) <= math.ceil(math.log2(n)) + 1
            assert notarylib.verify_consistency(m, notarylib.mth(leaves[:m]), n, root, proof)
            assert not notarylib.verify_consistency(m, notarylib.mth(leaves[:m]), n, root, proof[1:])
            bad = list(proof)
            bad[0] = _flip(bad[0])
            assert not notarylib.verify_consistency(m, notarylib.mth(leaves[:m]), n, root, bad)
        # Same-size "proof" only holds for the identical root.
        assert notarylib.verify_consistency(n, root, n, root, [])
        assert not notarylib.verify_consistency(n, root, n, _flip(root), [])


# --------------------------------------------------------------------------- #
# 1. First registration: verifiable membership proof; device switches slots
# --------------------------------------------------------------------------- #
def test_first_registration_returns_verifiable_proof_and_slot_switch(
    client, admin, make_device
):
    admin.ensure_root()
    img, _ = admin.upload_image(auto_release=False)
    r = admin.publish_release(img)
    body = r.json()
    assert body["duplicate"] is False

    # The publish response carries a membership proof that verifies against
    # the signed checkpoint, itself signed by the service's notary key.
    proof = body["notary"]
    info = client.get("/api/admin/notary/info").json()
    assert proof["checkpoint"]["tree_size"] == 2  # root handoff + this release
    assert notarylib.verify_checkpoint_signature(proof["checkpoint"], info["public_key"])
    assert notarylib.verify_inclusion(
        proof["entry"],
        proof["leaf_index"],
        proof["checkpoint"]["tree_size"],
        proof["inclusion"],
        proof["checkpoint"]["root_hash"],
    )
    # The notarized entry binds exactly this release envelope.
    assert proof["entry"]["content_hash"] == body["content_hash"]
    assert proof["entry"]["artifact_sha256"] == img["sha256"]

    # The device verifies both proofs at fetch time and completes the switch.
    _offer_campaign(admin, img)
    d = make_device("d1")
    d.register()
    ci = d.check_in()
    assert ci["offered"] is True
    assert ci["offer"]["notary"]["checkpoint"]["tree_size"] == 2
    d.download()
    assert d.install()["result"] == "installed"
    assert d.active_slot == "B"

    # The verified checkpoint persists across a process restart.
    d2 = make_device("d1")
    assert d2._notary["tree_size"] == 2
    assert d2._notary["root_hash"] == proof["checkpoint"]["root_hash"]


# --------------------------------------------------------------------------- #
# 2. Dormant device: one log-sized consistency proof across many growths
# --------------------------------------------------------------------------- #
def test_dormant_device_catches_up_with_log_sized_consistency(client, admin, make_device):
    img1, _ = admin.upload_image(version="2.0.0")
    b1 = _offer_campaign(admin, img1)
    d = make_device("d1")
    d.register()
    d.check_in()
    d.download()
    d.install()
    assert d._notary["tree_size"] == 2  # checkpoint remembered before sleeping
    admin.action(b1["id"], "complete")

    # The ledger grows many times while the device sleeps: two trust-root
    # handoffs and four releases for other models each append a leaf.
    keys2 = admin.kit.keyset(admin.kit.root2_pub, [admin.kit.rel_pub])
    admin.rotate_root(2, keys2, [admin.kit.root_priv, admin.kit.root2_priv])
    keys3 = admin.kit.keyset(admin.kit.root3_pub, [admin.kit.rel_pub])
    admin.rotate_root(3, keys3, [admin.kit.root2_priv, admin.kit.root3_priv])
    for i in range(4):
        admin.upload_image(model="term-x2", version=f"1.0.{i}", blob_seed=f"X2-{i}".encode())

    img2, _ = admin.upload_image(version="2.0.1", blob_seed=b"FW-2.0.1")
    _offer_campaign(admin, img2)
    total = _tree(client)["tree_size"]
    assert total == 9  # 2 + 2 rotations + 4 other releases + this release

    # One wake-up: the response carries the membership proof plus ONE
    # consistency proof spanning all seven growths — logarithmic, never the
    # full history.
    body = d.check_in()
    assert body["offered"] is True
    notary = body["offer"]["notary"]
    assert notary["checkpoint"]["tree_size"] == total
    transferred = len(notary["consistency"]) + len(notary["inclusion"])
    assert len(notary["consistency"]) <= math.ceil(math.log2(total)) + 1
    assert transferred < total  # log-scale, not full history
    assert "leaves" not in notary and "history" not in notary

    # The device connected its stored checkpoint (size 2) to the current one
    # and committed the new checkpoint with the fetch.
    assert d._notary["tree_size"] == total
    on_disk = json.loads((d.workdir / "notary.json").read_text())
    assert on_disk["tree_size"] == total
    assert on_disk["accepted"]["assignment_id"] == body["offer"]["assignment_id"]

    d.download()
    assert d.install()["result"] == "installed"
    assert d._trust.root_version == 3  # root chain caught up too


# --------------------------------------------------------------------------- #
# 3. Tampered membership proof: path closes before disk, evidence deduped
# --------------------------------------------------------------------------- #
def test_flipped_inclusion_proof_quarantines_before_disk(client, admin, make_device):
    img, _ = admin.upload_image()
    _offer_campaign(admin, img)

    def rewrite(body):
        if body.get("offer") and body["offer"].get("notary"):
            n = body["offer"]["notary"]
            if n["inclusion"]:
                n["inclusion"][-1] = _flip(n["inclusion"][-1])  # 翻转成员见证字节
            else:
                n["entry"]["content_hash"] = _flip(n["entry"]["content_hash"])
        return body

    d = _mitm_device(make_device("d1"), client, rewrite)
    d.register()
    with pytest.raises(notarylib.NotaryError) as e1:
        d.check_in()
    assert e1.value.kind == notarylib.KIND_INCLUSION

    # The path closed BEFORE any disk write: no download, no flash, the
    # active slot is untouched and still bootable.
    assert d._offer is None
    assert d.active_slot == "A" and d.slots["B"] is None
    assert d.facts["current_version"] == "1.9.0"
    events = client.get("/api/device/events", headers=h("d1")).json()
    assert not [e for e in events if e["event_type"] in ("downloading", "installing")]

    # The model is quarantined; the material is queryable exactly once.
    ev = _evidence(client, "term-x1")
    assert len(ev) == 1
    assert ev[0]["kind"] == notarylib.KIND_INCLUSION
    assert [q["model"] for q in _quarantine(client)] == ["term-x1"]

    # New fetches for the model are refused.
    body = client.post("/api/device/check-in", headers=h("d1")).json()
    assert body["offered"] is False
    assert body["reason"] == "model_quarantined"

    # The same material reported again (any number of times, any device)
    # stays a single stored copy.
    payload = {
        "kind": ev[0]["kind"],
        "evidence": ev[0]["evidence"],
        "idempotency_key": "replay-" + uuid.uuid4().hex,
    }
    r1 = client.post("/api/device/notary-evidence", headers=h("d1"), json=payload)
    assert r1.json()["duplicate"] is True
    admin.register_device("d2")
    r2 = client.post("/api/device/notary-evidence", headers=h("d2"), json=payload)
    assert r2.json()["duplicate"] is True
    assert len(_evidence(client, "term-x1")) == 1


# --------------------------------------------------------------------------- #
# 4. Broken history linkage (dropped entries) quarantines before disk
# --------------------------------------------------------------------------- #
def test_broken_consistency_quarantines_before_disk(client, admin, make_device):
    img, _ = admin.upload_image()
    _offer_campaign(admin, img)
    d = make_device("d1")
    d.register()
    d.check_in()  # accepts the offer, stores checkpoint at tree size 2
    assert d._notary["tree_size"] == 2

    # The tree grows honestly while the device is away.
    keys2 = admin.kit.keyset(admin.kit.root2_pub, [admin.kit.rel_pub])
    admin.rotate_root(2, keys2, [admin.kit.root_priv, admin.kit.root2_priv])

    # ... but the served consistency proof cannot connect the old entries
    # (a history-rewriting log drops the linking node).
    def rewrite(body):
        if body.get("offer") and body["offer"].get("notary"):
            n = body["offer"]["notary"]
            if n["consistency"]:
                n["consistency"] = n["consistency"][1:]
        return body

    _mitm_device(d, client, rewrite)
    with pytest.raises(notarylib.NotaryError) as e1:
        d.check_in()
    assert e1.value.kind == notarylib.KIND_CONSISTENCY

    # Stopped before touching disk; the active slot still boots.
    assert d.active_slot == "A" and d.slots["B"] is None
    events = client.get("/api/device/events", headers=h("d1")).json()
    assert not [e for e in events if e["event_type"] == "installing"]
    assert len(_evidence(client, "term-x1")) == 1
    assert _evidence(client, "term-x1")[0]["kind"] == notarylib.KIND_CONSISTENCY

    # The stored checkpoint was NOT advanced by the failed verification.
    assert d._notary["tree_size"] == 2
    assert json.loads((d.workdir / "notary.json").read_text())["tree_size"] == 2


# --------------------------------------------------------------------------- #
# 5. A smaller (replayed) tree height quarantines before disk
# --------------------------------------------------------------------------- #
def test_smaller_tree_height_quarantines_before_disk(client, admin, make_device):
    img, _ = admin.upload_image()
    _offer_campaign(admin, img)
    d = make_device("d1")
    d.register()
    d.check_in()
    assert d._notary["tree_size"] == 2

    # The attacker replays the genuine, validly-signed size-1 checkpoint.
    old_cp = _tree(client)["checkpoints"][0]
    assert old_cp["tree_size"] == 1

    def rewrite(body):
        if body.get("offer") and body["offer"].get("notary"):
            body["offer"]["notary"]["checkpoint"] = {
                "tree_size": old_cp["tree_size"],
                "root_hash": old_cp["root_hash"],
                "signature": old_cp["signature"],
            }
        return body

    _mitm_device(d, client, rewrite)
    with pytest.raises(notarylib.NotaryError) as e1:
        d.check_in()
    assert e1.value.kind == notarylib.KIND_TREE_SHRANK

    assert d.active_slot == "A" and d.slots["B"] is None
    assert d._notary["tree_size"] == 2  # checkpoint not rolled back
    ev = _evidence(client, "term-x1")
    assert len(ev) == 1 and ev[0]["kind"] == notarylib.KIND_TREE_SHRANK
    body = client.post("/api/device/check-in", headers=h("d1")).json()
    assert body["reason"] == "model_quarantined"


# --------------------------------------------------------------------------- #
# 6. Split view: two validly-signed same-size checkpoints, different roots
# --------------------------------------------------------------------------- #
def test_split_view_checkpoint_quarantines_and_survives_restart(
    client, admin, make_device
):
    img, _ = admin.upload_image()
    _offer_campaign(admin, img)
    d = make_device("d1")
    d.register()
    d.check_in()
    assert d._notary["tree_size"] == 2

    # A compromised notary signs a SECOND checkpoint for the same tree size
    # with a different root — both signatures verify against the pinned key.
    priv = _notary_private_key()
    fork_root = _flip(d._notary["root_hash"])
    fork_sig = notarylib.sign_checkpoint(2, fork_root, priv)
    assert notarylib.verify_checkpoint_signature(
        {"tree_size": 2, "root_hash": fork_root, "signature": fork_sig},
        d._notary["notary_public"],
    )

    def rewrite(body):
        if body.get("offer") and body["offer"].get("notary"):
            body["offer"]["notary"]["checkpoint"] = {
                "tree_size": 2,
                "root_hash": fork_root,
                "signature": fork_sig,
            }
        return body

    _mitm_device(d, client, rewrite)
    with pytest.raises(notarylib.NotaryError) as e1:
        d.check_in()
    assert e1.value.kind == notarylib.KIND_SPLIT_VIEW

    assert d.active_slot == "A" and d.slots["B"] is None
    ev = _evidence(client, "term-x1")
    assert len(ev) == 1 and ev[0]["kind"] == notarylib.KIND_SPLIT_VIEW
    assert [q["model"] for q in _quarantine(client)] == ["term-x1"]

    # The quarantine is durable: a fresh service process (same DB) still
    # refuses new fetches for the model.
    from app.main import app

    with TestClient(app) as c2:
        body = c2.post("/api/device/check-in", headers=h("d1")).json()
        assert body["offered"] is False
        assert body["reason"] == "model_quarantined"
        assert [q["model"] for q in c2.get("/api/admin/notary/quarantine").json()] == ["term-x1"]
        assert len(c2.get("/api/admin/notary/evidence").json()) == 1


# --------------------------------------------------------------------------- #
# 7. Crash between artifact record and leaf commit: no orphan, no double leaf
# --------------------------------------------------------------------------- #
def test_crash_between_record_and_leaf_leaves_no_orphan_no_double_leaf(
    client, admin, make_device, monkeypatch
):
    admin.ensure_root()
    img, _ = admin.upload_image(auto_release=False)
    _offer_campaign(admin, img)

    from app import notarization

    real_append = notarization.append_entry
    calls = {"n": 0}

    def kill_between(db, entry_type, ref_id, entry):
        # The release row is already staged in the transaction; the process
        # dies before the leaf (and checkpoint) land.
        if entry_type == "release":
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("kill -9 between record and leaf")
        return real_append(db, entry_type, ref_id, entry)

    monkeypatch.setattr(notarization, "append_entry", kill_between)

    meta = trustlib.release_metadata(
        model=img["model"],
        version=img["version"],
        artifact_sha256=img["sha256"],
        security_counter=1,
        expires=trustlib.iso_after(30 * 86400),
    )
    sigs = [trustlib.sign_envelope(meta, admin.kit.rel_priv)]
    token = "crash-" + uuid.uuid4().hex
    payload = {"image_id": img["id"], "metadata": meta, "signatures": sigs,
               "idempotency_key": token}

    with pytest.raises(RuntimeError):
        client.post("/api/admin/releases", json=payload)

    # No intermediate state is visible: no orphan release record, no leaf,
    # no checkpoint for it — and the artifact is NOT fetchable.
    assert client.get("/api/admin/releases").json() == []
    tree = _tree(client)
    assert tree["tree_size"] == 1  # the trust-root leaf only
    assert [l["entry_type"] for l in tree["leaves"]] == ["root"]
    admin.register_device("d1")
    body = client.post("/api/device/check-in", headers=h("d1")).json()
    assert body["offered"] is False
    assert body["reason"] == "no_signed_release"

    # The retried call with the SAME request token completes exactly once:
    # one business object, one leaf, one new checkpoint.
    r = client.post("/api/admin/releases", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["duplicate"] is False
    assert len(client.get("/api/admin/releases").json()) == 1
    tree = _tree(client)
    assert tree["tree_size"] == 2
    assert [l["entry_type"] for l in tree["leaves"]] == ["root", "release"]
    assert [c["tree_size"] for c in tree["checkpoints"]] == [1, 2]

    # ... and the recovered artifact is fetchable with verifiable proofs.
    d = make_device("d1")
    d.register()
    assert d.check_in()["offered"] is True
    d.download()
    assert d.install()["result"] == "installed"


# --------------------------------------------------------------------------- #
# 8. Six concurrent calls sharing one request token: one object, one leaf
# --------------------------------------------------------------------------- #
def test_six_concurrent_publications_share_token_one_object_one_leaf(client, admin):
    admin.ensure_root()
    img, _ = admin.upload_image(auto_release=False)
    meta = trustlib.release_metadata(
        model=img["model"],
        version=img["version"],
        artifact_sha256=img["sha256"],
        security_counter=1,
        expires=trustlib.iso_after(30 * 86400),
    )
    sigs = [trustlib.sign_envelope(meta, admin.kit.rel_priv)]
    body = {
        "image_id": img["id"],
        "metadata": meta,
        "signatures": sigs,
        "idempotency_key": "shared-" + uuid.uuid4().hex,
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
    # One business object ...
    assert len({r.json()["id"] for r in results}) == 1
    assert sum(1 for r in results if r.json()["duplicate"] is False) == 1
    assert len(client.get("/api/admin/releases").json()) == 1
    # ... and the tree grew exactly once, with every response pointing at the
    # same leaf.
    assert len({r.json()["notary"]["leaf_index"] for r in results}) == 1
    tree = _tree(client)
    assert tree["tree_size"] == 2
    assert [l["entry_type"] for l in tree["leaves"]] == ["root", "release"]
    assert [c["tree_size"] for c in tree["checkpoints"]] == [1, 2]


# --------------------------------------------------------------------------- #
# 9. Quarantine: flashing device finishes; untouched device stops
# --------------------------------------------------------------------------- #
def test_quarantine_lets_flashing_device_finish_but_stops_others(
    client, admin, make_device
):
    img, _ = admin.upload_image()
    b = _offer_campaign(admin, img)

    d1 = make_device("d1")  # enters the flash critical region
    d1.register()
    d1.check_in()
    d1.download()
    d1._event("installing", {"slot": "B"})

    d2 = make_device("d2")  # downloaded but never started flashing
    d2.register()
    d2.check_in()
    d2.download()
    assert d2._offer["install_state"] == "downloaded"

    # A third device reports notary misbehavior -> the model is quarantined.
    d3 = make_device("d3")
    d3.register()
    r = d3.client.post(
        "/api/device/notary-evidence",
        headers=d3._h(),
        json={
            "kind": notarylib.KIND_SPLIT_VIEW,
            "evidence": {"detail": "forked checkpoint", "served_checkpoint": {"tree_size": 2}},
            "idempotency_key": "ev-" + uuid.uuid4().hex,
        },
    )
    assert r.status_code == 200
    assert r.json()["quarantined"] is True

    # d1 is already rewriting the standby slot: it may finish and report.
    body = d1.check_in()
    assert body["offered"] is True
    assert body["offer"]["finalize_only"] is True
    res = d1._event("installed", {"version": "2.0.0", "slot": "B"})
    assert res["to_state"] == "installed"

    # d2 has not touched disk: every path forward is closed.
    body = d2.check_in()
    assert body["offered"] is False
    assert body["reason"] == "model_quarantined"
    r = client.get(
        f"/api/device/artifacts/{img['id']}/chunks/0",
        params={"assignment_id": d2._offer["assignment_id"]},
        headers=h("d2"),
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "model_quarantined"
    r = client.post(
        "/api/device/events",
        headers=h("d2"),
        json={
            "assignment_id": d2._offer["assignment_id"],
            "event_type": "installing",
            "idempotency_key": "installing-after-quarantine",
            "payload": {},
        },
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "model_quarantined"

    # d2's local state is untouched: the active slot still boots 1.9.0.
    assert d2.active_slot == "A" and d2.slots["B"] is None
    asg = [
        a
        for a in client.get(f"/api/admin/assignments?batch_id={b['id']}").json()
        if a["device_id"] == "d2"
    ][0]
    assert asg["install_state"] == "downloaded"
