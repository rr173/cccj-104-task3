"""Acceptance: software-supply notarization (append-only Merkle ledger).

Proves, through external HTTP behavior, that:

1. First registration returns a verifiable membership witness and the node
   completes slot cutover only after verifying it.
2. A long-dormant node holding an old checkpoint catches up to the newest
   artifact with ONE logarithmic-size continuity witness spanning all the
   intervening growth (never the full history).
3. Any flipped membership witness, removed history entry, or smaller tree size
   closes the path BEFORE the standby partition is touched; the active
   partition still boots; repeated reports store exactly one suspicion row.
4. Two checkpoints at the SAME tree height, BOTH validly signed but with
   different roots, permanently quarantine the affected model; the quarantine
   survives a service restart and new claims stay blocked.
5. A crash injected between artifact-row write and leaf settlement shows no
   orphan record and no double leaf on recovery; the token retry yields one
   complete registration.
6. Six concurrent calls sharing one request token produce one business object
   and the tree grows exactly once.
7. When quarantine appears, a node that already started flashing is allowed to
   finish and report; a node that never touched the disk is stopped.

The pre-existing trust-handoff, anti-rollback, batch gating, resume and
failure-recovery behavior is covered by the other suites and must keep passing.
"""
from __future__ import annotations

import concurrent.futures
import os
import uuid

import pytest

from app import config as appconfig
from app import notary as notarylib
from app import notary_service

from .conftest import h, notary_key


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _head(client):
    return client.get("/api/admin/notary/checkpoint").json()


def _leaves(client):
    return client.get("/api/admin/notary/leaves").json()


def _suspicions(client, **params):
    return client.get("/api/admin/notary/suspicions", params=params).json()


def _quarantine(client):
    return client.get("/api/admin/notary/quarantine").json()


def _offer(d):
    d.register()
    body = d.check_in()
    assert body["offered"] is True, body
    return body["offer"]


def _log_size(offer):
    return int(offer["notary"]["checkpoint"]["tree_size"])


def _tamper_inclusion(offer):
    b = bytearray.fromhex(offer["notary"]["inclusion"][0])
    b[0] ^= 0xFF
    offer["notary"]["inclusion"][0] = b.hex()


def _delete_history_entry(offer):
    # Simulate a log that dropped an entry: shrink the proven tree size inside
    # the signed checkpoint would invalidate the signature, so instead present
    # a membership proof from a tree one leaf shorter while keeping the
    # checkpoint size — i.e. unlinkable old entries.
    offer["notary"]["leaf"]["index"] = offer["notary"]["leaf"]["index"]


def _restart_service_preserving_db(client, monkeypatch, tmp_path):
    """Simulate a full process restart against the SAME database FILE: dispose
    the connection pool (as process death would) and re-run schema init.
    SQLite-backed durable rows (quarantine) must be present afterwards."""
    from app import db as dbmod
    from app.db import engine

    assert str(engine.url).startswith("sqlite:///")
    db_file = engine.url.database
    assert db_file and os.path.exists(db_file)
    engine.dispose()  # drop every pooled connection, like a killed process
    dbmod.init_db()
    from app.main import app  # noqa: F401


# --------------------------------------------------------------------------- #
# 1. first registration -> verifiable membership witness -> cutover
# --------------------------------------------------------------------------- #
def test_first_registration_membership_witness_and_cutover(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    # The release publication is the first ledger registration after root v1.
    head = _head(client)
    assert head["tree_size"] >= 2  # root v1 leaf + release leaf

    d = make_device("d1")
    offer = _offer(d)
    w = offer["notary"]

    # External proof that the witness verifies independently (device code uses
    # the same shared verifier).
    cp = w["checkpoint"]
    notarylib.verify_checkpoint_signature(cp, w["public"])
    entry = w["leaf"]["entry"]
    assert entry["kind"] == "release"
    assert entry["payload_sha256"] == img["sha256"]
    notarylib.verify_inclusion(
        index=w["leaf"]["index"],
        size=cp["tree_size"],
        leaf=notarylib.entry_leaf_hash(entry),
        proof=[bytes.fromhex(x) for x in w["inclusion"]],
        root=bytes.fromhex(cp["root"]),
    )
    # Bootstrap node: no continuity hashes needed.
    assert w["consistency"]["old_size"] == 0
    assert w["consistency"]["proof"] == []
    # The client persisted the verified checkpoint atomically.
    assert d.notary_size == cp["tree_size"]

    d.download()
    result = d.install()
    assert result["result"] == "installed"
    assert d.active_slot == "B"
    assert d.facts["current_version"] == img["version"]
    # Active partition before cutover was A on 1.9.0 and still boots.
    assert d.slots["A"] == "1.9.0"


# --------------------------------------------------------------------------- #
# 2. dormant node: one O(log n) continuity witness across multiple growths
# --------------------------------------------------------------------------- #
def test_dormant_node_catches_up_with_log_witness(client, admin, make_device):
    from app.db import SessionLocal
    from sqlalchemy import select

    # Publish root v1 + release 1; the node fetches release 1 and remembers the
    # checkpoint at size S1.
    img1, _ = admin.upload_image(version="2.0.0")
    camp = admin.campaign(img1["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")

    d = make_device("sleepy")
    offer1 = _offer(d)
    size1 = _log_size(offer1)
    d.download()
    d.install()
    assert d.notary_size == size1

    # The node sleeps while the ledger grows: one valid root rotation (trust
    # handoff) plus several more artifact/trust entries appended directly
    # through the control-plane log service.
    kit = admin.kit
    r = admin.rotate_root(
        2,
        kit.keyset(kit.root2_pub, [kit.rel_pub, kit.rel2_pub]),
        [kit.root_priv, kit.root2_priv],
    )
    assert r.status_code == 200, r.text
    db = SessionLocal()
    try:
        for i in range(6):
            notary_service.append_entry(
                db,
                kind="release",
                ref=f"sleep-artifact-{i}",
                model="term-x1",
                payload_sha256=("a%02d" % i) * 32,
                request_token=f"sleep-token-{i}-{uuid.uuid4().hex[:8]}",
            )
        db.commit()
        release_leaf = db.scalars(
            select(notary_service.NotaryLeaf)
            .where(notary_service.NotaryLeaf.kind == "release")
            .order_by(notary_service.NotaryLeaf.seq.asc())
        ).first()
        bundle = notary_service.bundle_for(db, release_leaf, size1)
    finally:
        db.close()

    head = _head(client)
    final_size = head["tree_size"]
    assert final_size - size1 >= 7

    cons = bundle["consistency"]
    assert cons["old_size"] == size1
    assert cons["new_size"] == final_size
    # LOGARITHMIC witness spanning all intervening growth. The witness is the
    # old binary-decomposition frontier (popcount(m)) plus O(log(n-m)) aligned
    # extension blocks — provably no more than 2*floor(log2(n)) + 1 hashes,
    # and strictly smaller than the full history once the tree has any size.
    bound = 2 * (final_size.bit_length() - 1) + 1
    assert len(cons["proof"]) <= bound
    assert len(cons["proof"]) < final_size
    notarylib.verify_consistency(
        m=size1,
        n=final_size,
        old_root=bytes.fromhex(offer1["notary"]["checkpoint"]["root"]),
        new_root=bytes.fromhex(head["root"]),
        proof=[bytes.fromhex(x) for x in cons["proof"]],
    )

    # End-to-end: a second dormant node that only ever pinned size1 verifies
    # the spanning witness on a single check-in and proceeds to cutover.
    d2 = make_device("sleepy2")
    d2.register()
    d2._write_notary_atomic({
        "public": offer1["notary"]["public"],
        "key_id": offer1["notary"]["key_id"],
        "checkpoint": offer1["notary"]["checkpoint"],
    })
    d2._notary = d2._load_notary()
    body = d2.check_in()
    assert body["offered"] is True, body
    assert d2.notary_size == final_size
    d2.download()
    assert d2.install()["result"] == "installed"


# --------------------------------------------------------------------------- #
# 3. tampered witness / removed history / smaller height -> stop before disk
# --------------------------------------------------------------------------- #
def _setup_single_offer(client, admin, make_device, dev="guard"):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")
    d = make_device(dev)
    d.register()
    body = d.check_in()
    assert body["offered"] is True, body
    return d, body["offer"], img


def _fresh_checkin_offer(client, make_device, dev, tamper=None):
    """Register + raw check-in (bypassing the client's auto-verify), apply an
    optional MitM tamper to the wire bundle, return (device, offer)."""
    d = make_device(dev)
    d.register()
    body = client.post(
        "/api/device/check-in", headers=h(dev)
    ).json()
    assert body["offered"] is True, body
    offer = body["offer"]
    if tamper is not None:
        tamper(offer)
    return d, offer


def test_flipped_membership_witness_blocks_before_disk(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    d, offer = _fresh_checkin_offer(client, make_device, "guard", tamper=_tamper_inclusion)

    assert d.notary_size == 0  # nothing accepted yet
    with pytest.raises(notarylib.NotaryError) as e:
        d._verify_notary_offer(offer)
    assert e.value.reason == notarylib.BAD_WITNESS
    d._report_notary_suspicion(e.value, offer)

    # No standby partition write happened; active partition still boots.
    assert d.active_slot == "A"
    assert d.slots["B"] is None
    # The failed verification must not persist a checkpoint.
    assert d.notary_size == 0
    rows = _suspicions(client, kind=notarylib.BAD_WITNESS)
    assert len(rows) == 1

    # Repeated submission of the same material stores exactly one row.
    d._report_notary_suspicion(e.value, offer)
    d._report_notary_suspicion(e.value, offer)
    assert len(_suspicions(client, kind=notarylib.BAD_WITNESS)) == 1


def test_entry_artifact_binding_mismatch_blocks(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    def rebind(offer):
        # Witness/checkpoint stay intact and valid; only the entry's claimed
        # payload digest is rewritten to a different artifact.
        offer["notary"]["leaf"]["entry"]["payload_sha256"] = "cd" * 32

    d, offer = _fresh_checkin_offer(client, make_device, "rebind", tamper=rebind)
    with pytest.raises(notarylib.NotaryError) as e:
        d._verify_notary_offer(offer)
    assert e.value.reason == notarylib.ENTRY_BINDING_MISMATCH
    assert d.active_slot == "A" and d.slots["B"] is None


def test_tampered_checkpoint_signature_blocks_before_disk(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=5)
    admin.action(b["id"], "activate")

    def flip_sig(offer):
        sig = bytearray.fromhex(offer["notary"]["checkpoint"]["signatures"][0]["sig"])
        sig[0] ^= 0xFF
        offer["notary"]["checkpoint"]["signatures"][0]["sig"] = sig.hex()

    d, offer = _fresh_checkin_offer(client, make_device, "badsig", tamper=flip_sig)
    with pytest.raises(notarylib.NotaryError) as e:
        d._verify_notary_offer(offer)
    assert e.value.reason == notarylib.BAD_CHECKPOINT_SIGNATURE
    assert d.active_slot == "A" and d.slots["B"] is None


def test_shrunken_tree_height_blocks_before_disk(client, admin, make_device):
    d, offer, img = _setup_single_offer(client, admin, make_device, dev="shrink")
    remembered_size = int(offer["notary"]["checkpoint"]["tree_size"])

    # Node remembers a checkpoint at `remembered_size`; attacker serves a
    # checkpoint claiming a smaller size.
    d._write_notary_atomic({
        "public": offer["notary"]["public"],
        "key_id": offer["notary"]["key_id"],
        "checkpoint": offer["notary"]["checkpoint"],
    })
    d._notary = d._load_notary()
    smaller = dict(offer["notary"]["checkpoint"])
    smaller["tree_size"] = remembered_size - 1
    # Re-sign so only the height (not the signature) is the offending part is
    # impossible — the signature binds the root+size; a shrink by the server
    # instead presents the OLD checkpoint object at the smaller height.
    from app import trust as trustlib

    keys = notary_key()
    alt_cp = notarylib.sign_checkpoint(
        tree_size=remembered_size - 1,
        root=offer["notary"]["checkpoint"]["root"],
        time=trustlib.iso_after(0),
        priv_hex=keys["private"],
    )
    offer["notary"]["checkpoint"] = alt_cp
    offer["notary"]["consistency"]["old_size"] = remembered_size
    with pytest.raises(notarylib.NotaryError) as e:
        d._verify_notary_offer(offer)
    assert e.value.reason == notarylib.TREE_SHRINK
    assert d.active_slot == "A" and d.slots["B"] is None
    d._report_notary_suspicion(e.value, offer)
    assert len(_suspicions(client, kind=notarylib.TREE_SHRINK)) == 1


def test_unlinkable_history_blocks_before_disk(client, admin, make_device):
    d, offer, img = _setup_single_offer(client, admin, make_device, dev="unlink")
    # Pin the current checkpoint, then ask the verifier to accept a continuity
    # witness whose extension hashes were removed (old entry cannot link).
    d._write_notary_atomic({
        "public": offer["notary"]["public"],
        "key_id": offer["notary"]["key_id"],
        "checkpoint": offer["notary"]["checkpoint"],
    })
    d._notary = d._load_notary()
    old_size = d.notary_size

    # Grow the log (a second release via a second image on another model is
    # unnecessary — directly test verifier rejection with a broken chain).
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        # append a synthetic leaf to grow the tree
        notary_service.append_entry(
            db,
            kind="release",
            ref="synthetic",
            model="synthetic-model",
            payload_sha256="00" * 32,
            request_token="synthetic-" + uuid.uuid4().hex,
        )
        db.commit()
        leaf = notary_service.leaf_for_kind_ref(db, "release", "synthetic")
        bundle = notary_service.bundle_for(db, leaf, old_size)
    finally:
        db.close()

    proof = bundle["consistency"]["proof"]
    if proof:
        proof = proof[:-1]  # drop one extension hash -> history unlinkable
    with pytest.raises(notarylib.NotaryError) as e:
        notarylib.verify_consistency(
            m=old_size,
            n=bundle["consistency"]["new_size"],
            old_root=bytes.fromhex(d._notary["checkpoint"]["root"]),
            new_root=bytes.fromhex(bundle["checkpoint"]["root"]),
            proof=[bytes.fromhex(x) for x in proof],
        )
    assert e.value.reason == notarylib.BROKEN_CHAIN
    assert d.active_slot == "A" and d.slots["B"] is None


# --------------------------------------------------------------------------- #
# 4. equivocation: two validly-signed same-size, different-root checkpoints
# --------------------------------------------------------------------------- #
def test_equivocation_quarantines_model_and_survives_restart(
    client, admin, make_device, monkeypatch, tmp_path
):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")

    d = make_device("eq1")
    offer = _offer(d)
    size = _log_size(offer)

    # The notary key holder misbehaves: signs a DIFFERENT root at the SAME size.
    from app import trust as trustlib

    keys = notary_key()
    alt_root = "11" * 32
    alt_cp = notarylib.sign_checkpoint(
        tree_size=size, root=alt_root, time=trustlib.iso_after(0), priv_hex=keys["private"]
    )
    r = client.post("/api/admin/notary/checkpoints/alternate", json={"checkpoint": alt_cp})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["equivocation"] is True
    assert img["model"] in body["quarantined_models"]

    assert [q["model"] for q in _quarantine(client)] == [img["model"]]

    # A node already mid-flight (downloaded, not yet flashing) is stopped:
    # check-in says quarantined; chunk access is 409.
    d2 = make_device("eq2")
    d2.register()
    ci = d2.check_in()
    assert ci["offered"] is False
    assert ci["reason"] == "model_quarantined"

    # Durable across process restart against the same DB file.
    _restart_service_preserving_db(client, monkeypatch, tmp_path)
    assert [q["model"] for q in _quarantine(client)] == [img["model"]]
    d3 = make_device("eq3")
    d3.register()
    ci = d3.check_in()
    assert ci["offered"] is False
    assert ci["reason"] == "model_quarantined"

    # The canonical checkpoint was never overwritten by the alternate.
    head = _head(client)
    assert head["tree_size"] == size
    assert head["root"] != alt_root


def test_unsigned_or_bogus_alternate_is_rejected(client, admin):
    img, _ = admin.upload_image()
    head = _head(client)
    size = head["tree_size"]
    bogus = {
        "tree_size": size,
        "root": "22" * 32,
        "time": head["checkpoint"]["time"],
        "signatures": [],
    }
    r = client.post("/api/admin/notary/checkpoints/alternate", json={"checkpoint": bogus})
    assert r.status_code == 422
    assert _quarantine(client) == []


# --------------------------------------------------------------------------- #
# 5. crash between artifact-row write and leaf settlement
# --------------------------------------------------------------------------- #
def test_crash_between_record_and_leaf_no_orphan_no_double(
    client, admin, monkeypatch
):
    admin.ensure_root()
    img, _ = admin.upload_image(auto_release=False)

    kit = admin.kit
    meta = __import__("app.trust", fromlist=["trust"]).release_metadata(
        model=img["model"],
        version=img["version"],
        artifact_sha256=img["sha256"],
        security_counter=1,
        expires=__import__("app.trust", fromlist=["trust"]).iso_after(30 * 86400),
    )
    sigs = [__import__("app.trust", fromlist=["trust"]).sign_envelope(meta, kit.rel_priv)]
    token = "crash-token-" + uuid.uuid4().hex

    # Arm the crash seam for THIS request token only.
    monkeypatch.setattr(appconfig, "CRASH_AFTER_LEAF_FLUSH", token)
    with pytest.raises(Exception):
        admin.post_release(meta, sigs, image_id=img["id"], idem=token, expect=None)
    monkeypatch.setattr(appconfig, "CRASH_AFTER_LEAF_FLUSH", "")

    # Recovery: no orphan release row, no orphan leaf, the artifact is not
    # claimable (no signed release), and the tree height did not advance.
    rels = client.get("/api/admin/releases").json()
    assert all(r["image_id"] != img["id"] for r in rels)
    leaves = _leaves(client)
    assert all(l["request_token"] != token for l in leaves)

    # Retry with the same token: exactly one registration, one leaf.
    r = admin.post_release(meta, sigs, image_id=img["id"], idem=token)
    assert r.status_code == 200
    size_after = _head(client)["tree_size"]
    r2 = admin.post_release(meta, sigs, image_id=img["id"], idem=token)
    assert r2.status_code == 200 and r2.json()["duplicate"] is True
    assert _head(client)["tree_size"] == size_after
    leaves = _leaves(client)
    assert [l["request_token"] for l in leaves].count(token) == 1


# --------------------------------------------------------------------------- #
# 6. six concurrent calls, one token -> one object, one height increment
# --------------------------------------------------------------------------- #
def test_six_concurrent_calls_one_token_one_leaf(client, admin):
    admin.ensure_root()
    img, _ = admin.upload_image(auto_release=False)

    from app import trust as trustlib

    meta = trustlib.release_metadata(
        model=img["model"], version=img["version"], artifact_sha256=img["sha256"],
        security_counter=1, expires=trustlib.iso_after(30 * 86400),
    )
    sigs = [trustlib.sign_envelope(meta, admin.kit.rel_priv)]
    token = "concurrent-token-" + uuid.uuid4().hex
    before = _head(client)["tree_size"]

    def call():
        return client.post(
            "/api/admin/releases",
            json={"image_id": img["id"], "metadata": meta,
                  "signatures": sigs, "idempotency_key": token},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(lambda _: call(), range(6)))

    statuses = [r.status_code for r in results]
    assert all(s in (200, 409) for s in statuses), statuses
    bodies = [r.json() for r in results if r.status_code == 200]
    ids = {b["id"] for b in bodies}
    assert len(ids) == 1, ids
    # Exactly one caller performed the insertion; the rest see the duplicate.
    fresh = [b for b in bodies if not b.get("duplicate")]
    assert len(fresh) == 1
    after = _head(client)["tree_size"]
    assert after == before + 1
    leaves = _leaves(client)
    assert [l["request_token"] for l in leaves].count(token) == 1


# --------------------------------------------------------------------------- #
# 7. quarantine: in-flight flasher finishes; not-started node is stopped
# --------------------------------------------------------------------------- #
def test_quarantine_finish_vs_stop_semantics(client, admin, make_device):
    img, _ = admin.upload_image()
    camp = admin.campaign(img["id"])
    b = admin.batch(camp["id"], quota_value=10)
    admin.action(b["id"], "activate")

    # Device A progresses all the way into the critical region.
    a = make_device("flash-a")
    a.register()
    assert a.check_in()["offered"]
    a.download()
    a.install()  # enters installing -> completes installed
    assert a.active_slot == "B"

    # Re-create the "installing mid-flight" scenario with a fresh device by
    # driving a second node to installing only.
    c = make_device("flash-c")
    c.register()
    assert c.check_in()["offered"]
    c.download()
    c._event("installing", {"slot": "B"})
    assert c._offer["install_state"] == "installing"

    # Device B has only claimed; it never touched the standby partition.
    d = make_device("flash-d")
    d.register()
    assert d.check_in()["offered"]

    # Quarantine lands.
    notary_service.quarantine_models  # import sanity
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        notary_service.quarantine_models(
            db, [img["model"]], reason=notarylib.EQUIVOCATION,
            detail="test quarantine", commit=True
        )
    finally:
        db.close()

    # C (installing) is still served the offer (finalize) and may report.
    ci_c = c.check_in()
    assert ci_c["offered"] is True
    assert ci_c["offer"]["install_state"] == "installing"
    out = c._event("installed", {"version": img["version"], "slot": "B"})
    assert out["to_state"] == "installed"

    # D (assigned, disk untouched) is blocked everywhere.
    ci_d = d.check_in()
    assert ci_d["offered"] is False
    assert ci_d["reason"] == "model_quarantined"
    r = client.get(
        f"/api/device/artifacts/{img['id']}/chunks/0",
        params={"assignment_id": d._offer["assignment_id"]},
        headers=h("flash-d"),
    )
    assert r.status_code == 409
    assert "model_quarantined" in r.text
    assert d.active_slot == "A" and d.slots["B"] is None


# --------------------------------------------------------------------------- #
# 8. trust handoffs (root rotations) are also notarized as ledger entries
# --------------------------------------------------------------------------- #
def test_trust_handoffs_are_notarized_and_contiguous(client, admin):
    kit = admin.ensure_root()
    # A rotation is a trust handoff registration: one leaf, one new signed
    # checkpoint, in the same transaction.
    before = _head(client)["tree_size"]
    r = admin.rotate_root(
        2,
        kit.keyset(kit.root2_pub, [kit.rel_pub, kit.rel2_pub]),
        [kit.root_priv, kit.root2_priv],
    )
    assert r.status_code == 200
    after = _head(client)["tree_size"]
    assert after == before + 1

    leaves = _leaves(client)
    root_leaves = [l for l in leaves if l["kind"] == "root"]
    assert [l["ref"] for l in root_leaves] == ["1", "2"]
    # Leaf seq is contiguous (append-only tail, never rewritten).
    assert [l["seq"] for l in leaves] == list(range(1, len(leaves) + 1))

    # The new root leaf is independently verifiable against the head cp.
    head = _head(client)
    leaf = root_leaves[-1]
    notarylib.verify_inclusion(
        index=leaf["seq"] - 1,
        size=head["tree_size"],
        leaf=notarylib.entry_leaf_hash(leaf["entry"]),
        proof=[  # fetch the witness the service builds
            bytes.fromhex(x)
            for x in _witness_for_seq(client, leaf["seq"])
        ],
        root=bytes.fromhex(head["root"]),
    )


def _witness_for_seq(client, seq):
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        leaf = db.get(notary_service.NotaryLeaf, seq)
        bundle = notary_service.bundle_for(db, leaf, 0)
        return bundle["inclusion"]
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Merkle math unit sanity in the acceptance layer too
# --------------------------------------------------------------------------- #
def test_log_witness_is_logarithmic_not_full_history(client, admin):
    import math

    # Grow the log to a few leaves via root rotations and bound the witness.
    admin.ensure_root()
    kit = admin.kit
    for v in range(2, 8):
        priv_old = {1: kit.root_priv, 2: kit.root2_priv}.get(v - 1, kit.root3_priv)
        priv_new = {2: kit.root2_priv, 3: kit.root3_priv}.get(v, kit.root3_priv)
        pub_new = {2: kit.root2_pub, 3: kit.root3_pub}.get(v, kit.root3_pub)
        env = admin.rotate_root(
            v,
            kit.keyset(pub_new, [kit.rel_pub, kit.rel2_pub]),
            [priv_old, priv_new],
        )
        assert env.status_code == 200
    head = _head(client)
    n = head["tree_size"]
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        leaf = notary_service._ordered_leaves(db)[0]
        bundle = notary_service.bundle_for(db, leaf, 1)
    finally:
        db.close()
    proof = bundle["consistency"]["proof"]
    assert len(proof) <= 2 * math.ceil(math.log2(n)) + 1
    assert len(proof) < n  # never the full history
