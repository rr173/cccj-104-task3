"""Minimal FOTA client that runs ON the terminal.

It models the parts the problem statement cares about:
* register + periodic check-in, safe to repeat at any time
* block downloads with per-block sha256 verification; on reconnect it only
  re-fetches blocks it does not already hold verbatim (resume from verified)
* offline trust: the device keeps a persisted trust store (current root chain
  version + highest accepted security counter) and validates the signed
  release envelope — trust chain, signatures, expiry, artifact digest and
  counter — BEFORE entering the critical write phase
* supply-chain notarization: every offer carries the release's Merkle
  membership proof plus the consistency path from the device's stored
  checkpoint; the device verifies BOTH before touching the standby slot and
  commits the new signed checkpoint together with the fetch result as ONE
  atomic state change (tmp file + rename). Notary misbehavior (split-view
  checkpoint, shrunk tree, broken consistency, tampered proof bytes) is
  reported as content-deduped evidence and fails closed: the active boot
  slot is never touched
* rejection fails closed: the active boot slot is never touched and the device
  posts a durable, idempotent `release_rejected` receipt
* A/B slot install: on failure the new slot is marked bad, the device boots the
  previous slot and posts `failed` + `rollback_complete` with the reason
* every POST carries a stable idempotency key; retried receipts are harmless
* trust-store writes are atomic (tmp file + rename): a power cut mid-rotation
  leaves either the old or the new trust state, never a half-applied one
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app import notary as notarylib
from app import trust as trustlib


class SimDevice:
    def __init__(
        self,
        base_url: str,
        *,
        device_id: str,
        model: str,
        hardware_batch: str,
        bootloader: str,
        current_version: str,
        workdir: Path,
        fail_install: bool = False,
        timeout: float = 10.0,
    ):
        self.client = httpx.Client(base_url=base_url, timeout=timeout)
        self.device_id = device_id
        self.facts = {
            "id": device_id,
            "model": model,
            "hardware_batch": hardware_batch,
            "bootloader": bootloader,
            "current_version": current_version,
        }
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.fail_install = fail_install
        self.slots = {"A": current_version, "B": None}
        self.active_slot = "A"
        self._offer: dict | None = None
        self._clock: float | None = None  # tests may pin/advance the device clock
        self._trust: trustlib.TrustStore | None = None
        self._notary: dict | None = None  # persisted verified checkpoint state
        self._idem = self._load_idem()
        self._load_persisted_state()  # survive process restart / power loss

    # ----- device clock (real devices use secure monotonic time) -----
    def _now(self) -> datetime:
        ts = self._clock if getattr(self, "_clock", None) is not None else time.time()
        return datetime.fromtimestamp(ts, timezone.utc)

    # ----- state persistence across process restarts -----
    @property
    def _state_path(self) -> Path:
        return self.workdir / "state.json"

    def _load_persisted_state(self) -> None:
        if self._state_path.exists():
            st = json.loads(self._state_path.read_text())
            self.slots = st["slots"]
            self.active_slot = st["active_slot"]
            self.facts["current_version"] = st["current_version"]
        self._trust = self._load_trust()
        self._notary = self._load_notary()

    def _save_state(self) -> None:
        self._state_path.write_text(
            json.dumps(
                {
                    "slots": self.slots,
                    "active_slot": self.active_slot,
                    "current_version": self.facts["current_version"],
                }
            )
        )

    # ----- persisted trust store (root chain head + anti-rollback counter) -----
    @property
    def _trust_path(self) -> Path:
        return self.workdir / "trust.json"

    def _load_trust(self) -> trustlib.TrustStore | None:
        if self._trust_path.exists():
            return trustlib.TrustStore.from_dict(json.loads(self._trust_path.read_text()))
        return None

    def _write_trust_atomic(self, trust: trustlib.TrustStore) -> None:
        """tmp-file + rename: interruption mid-rotation never exposes a
        half-applied trust state — the old file stays valid until the rename."""
        tmp = self._trust_path.with_name(self._trust_path.name + ".tmp")
        tmp.write_text(json.dumps(trust.to_dict()))
        os.replace(tmp, self._trust_path)

    # ----- persisted notary state (verified checkpoint + accepted fetch) -----
    @property
    def _notary_path(self) -> Path:
        return self.workdir / "notary.json"

    def _load_notary(self) -> dict | None:
        if self._notary_path.exists():
            return json.loads(self._notary_path.read_text())
        return None

    def _write_notary_atomic(self, state: dict) -> None:
        """The new checkpoint and the fetch result it authorizes are ONE
        indivisible state change: a single tmp-file + rename. A power cut
        leaves either the old checkpoint with the old fetch view, or the new
        pair — never a checkpoint that outlives the fetch it approved."""
        tmp = self._notary_path.with_name(self._notary_path.name + ".tmp")
        tmp.write_text(json.dumps(state))
        os.replace(tmp, self._notary_path)

    # ----- persistence / idempotency keys -----
    @property
    def _idem_path(self) -> Path:
        return self.workdir / "idem.json"

    def _load_idem(self) -> dict[str, str]:
        if self._idem_path.exists():
            return json.loads(self._idem_path.read_text())
        return {}

    def _idem_key(self, key_name: str) -> str:
        """Stable key per named milestone; a fresh name => fresh key."""
        v = self._idem.get(key_name)
        if not v:
            v = hashlib.sha256(
                f"{self.device_id}:{key_name}:{time.time_ns()}".encode()
            ).hexdigest()[:32]
            self._idem[key_name] = v
            self._idem_path.write_text(json.dumps(self._idem))
        return v

    def _event(self, event_type: str, payload: dict | None = None, *, key: str | None = None):
        # Milestone keys are scoped per assignment: a device that joins several
        # campaigns over its lifetime must not let campaign N+1's receipts be
        # deduped against campaign N's identical milestone keys.
        scope = self._offer["assignment_id"] if self._offer else "nooffer"

        def post(key_name: str):
            return self.client.post(
                "/api/device/events",
                headers=self._h(),
                json={
                    "assignment_id": self._offer["assignment_id"] if self._offer else None,
                    "event_type": event_type,
                    "idempotency_key": self._idem_key(f"{scope}:{key_name}"),
                    "payload": payload or {},
                },
            )

        r = post(key or event_type)
        if r.status_code == 409 and "illegal_transition" in r.text:
            # Local FSM view is stale (crash between server commit and local
            # persistence). Resync once and retry with a fresh milestone key.
            self.check_in()
            r = post(f"{key or event_type}:resync:{time.time_ns()}")
        r.raise_for_status()
        out = r.json()
        if out.get("to_state"):
            self._offer["install_state"] = out["to_state"]
        return out

    def _post_rejection(self, reason: str, detail: str, metadata: dict | None):
        """Durable failure receipt for a validation rejection. The idempotency
        key is derived from the rejection content, so reconnect replays dedup
        server-side (exactly one receipt row per distinct rejection)."""
        meta_hash = (
            hashlib.sha256(trustlib.canonical_json(metadata)).hexdigest()[:16]
            if isinstance(metadata, dict)
            else "-"
        )
        key = "rej-" + hashlib.sha256(
            f"{self.device_id}:{reason}:{detail}:{meta_hash}".encode()
        ).hexdigest()[:32]
        payload: dict = {"reason": reason, "detail": detail}
        if isinstance(metadata, dict):
            payload["release"] = {
                k: metadata.get(k)
                for k in ("release_id", "model", "version", "security_counter")
            }
        try:
            r = self.client.post(
                "/api/device/events",
                headers=self._h(),
                json={
                    "assignment_id": self._offer["assignment_id"] if self._offer else None,
                    "event_type": "release_rejected",
                    "idempotency_key": key,
                    "payload": payload,
                },
            )
            r.raise_for_status()
            return r.json()
        except Exception:
            return None  # never mask the original validation failure

    def close(self):
        self.client.close()

    # ----- API helpers -----
    def _h(self) -> dict:
        return {"X-Device-Id": self.device_id}

    def register(self):
        r = self.client.post("/api/device/register", json=self.facts)
        r.raise_for_status()
        return r.json()

    def check_in(self):
        root_version = self._trust.root_version if self._trust else 0
        tree_size = self._notary["tree_size"] if self._notary else 0
        r = self.client.post(
            "/api/device/check-in",
            headers={
                **self._h(),
                "X-Root-Version": str(root_version),
                "X-Notary-Tree-Size": str(tree_size),
            },
        )
        r.raise_for_status()
        body = r.json()
        notary_key = self._pin_notary_key(body.get("notary") or {})
        chain = ((body.get("trust") or {}).get("root_chain")) or []
        if chain:
            self._apply_root_chain(chain)
        if body.get("offer"):
            # Verify BOTH notary proofs before the offer may be used; the new
            # checkpoint and the accepted fetch commit as one atomic change.
            self._accept_offer(body["offer"], notary_key)
            self._offer = body["offer"]
        return body

    # ----- supply-chain notarization: pin, verify, commit, report -----
    def _pin_notary_key(self, info: dict) -> str | None:
        """TOFU-pin the notary public key. A key that changes under a pinned
        device is itself evidence of a notary compromise — fail closed."""
        served = info.get("public_key")
        pinned = (self._notary or {}).get("notary_public")
        if served and pinned and served != pinned:
            self._report_notary_evidence(
                notarylib.KIND_CHECKPOINT_SIG,
                {
                    "detail": "notary key changed",
                    "pinned_key": pinned,
                    "served_key": served,
                },
            )
            raise notarylib.NotaryError(
                notarylib.KIND_CHECKPOINT_SIG, "notary key changed"
            )
        return pinned or served

    def _accept_offer(self, offer: dict, notary_key: str | None) -> None:
        """Verify the offer's membership + consistency proofs, then commit the
        new checkpoint and the fetch result atomically. Any cryptographic
        failure is reported as evidence and fails closed BEFORE any download
        or flash write."""
        proof = offer.get("notary")
        envelope = offer.get("release")
        if not isinstance(proof, dict) or not isinstance(envelope, dict):
            # Absent/malformed notary section: reject locally (no quarantine —
            # there is no signed misbehavior to prove yet), never touch flash.
            self._post_rejection(
                trustlib.MISSING_METADATA, "offer carries no notary proof", None
            )
            raise trustlib.TrustError(
                trustlib.MISSING_METADATA, "offer carries no notary proof"
            )

        checkpoint = proof.get("checkpoint") or {}
        stored = self._notary

        def bail(kind: str, detail: str, extra: dict | None = None):
            evidence = {
                "detail": detail,
                "stored_checkpoint": (
                    {"tree_size": stored["tree_size"], "root_hash": stored["root_hash"]}
                    if stored
                    else None
                ),
                "served_checkpoint": {
                    "tree_size": checkpoint.get("tree_size"),
                    "root_hash": checkpoint.get("root_hash"),
                },
                "served_signature": checkpoint.get("signature"),
                "leaf_index": proof.get("leaf_index"),
                "inclusion": proof.get("inclusion"),
                "consistency": proof.get("consistency"),
                "entry": proof.get("entry"),
            }
            if extra:
                evidence.update(extra)
            self._report_notary_evidence(kind, evidence)
            raise notarylib.NotaryError(kind, detail)

        # 1. The checkpoint must be signed by the pinned notary key.
        if not notary_key or not notarylib.verify_checkpoint_signature(checkpoint, notary_key):
            bail(notarylib.KIND_CHECKPOINT_SIG, "checkpoint signature invalid")

        new_size = int(checkpoint["tree_size"])
        new_root = str(checkpoint["root_hash"])
        if stored is not None:
            old_size = int(stored["tree_size"])
            old_root = str(stored["root_hash"])
            # 2. The tree only grows: a smaller tree is a rollback attempt.
            if new_size < old_size:
                bail(notarylib.KIND_TREE_SHRANK, f"{new_size} < stored {old_size}")
            # 3. Same size must mean the same root (split-view detection).
            if new_size == old_size and new_root != old_root:
                bail(notarylib.KIND_SPLIT_VIEW, "same tree size, different root")
            # 4. Growth must connect the stored history to the new checkpoint.
            if new_size > old_size and not notarylib.verify_consistency(
                old_size, old_root, new_size, new_root, proof.get("consistency") or []
            ):
                bail(notarylib.KIND_CONSISTENCY, "old entries cannot be connected")

        # 5. The notarized entry must be the offered release itself ...
        entry = proof.get("entry")
        expected = trustlib.envelope_hash(
            envelope.get("metadata") or {}, envelope.get("signatures") or []
        )
        if not isinstance(entry, dict) or entry.get("content_hash") != expected:
            bail(notarylib.KIND_INCLUSION, "entry does not bind the offered release")
        # 6. ... and must sit inside the checkpoint's tree (tamper check).
        try:
            leaf_index = int(proof.get("leaf_index"))
        except (TypeError, ValueError):
            leaf_index = -1
        if not notarylib.verify_inclusion(
            entry, leaf_index, new_size, proof.get("inclusion") or [], new_root
        ):
            bail(notarylib.KIND_INCLUSION, "membership proof does not verify")

        # All proofs verified: commit {checkpoint + fetch result} atomically.
        self._write_notary_atomic(
            {
                "tree_size": new_size,
                "root_hash": new_root,
                "notary_public": notary_key,
                "accepted": {
                    "assignment_id": offer.get("assignment_id"),
                    "image_sha256": offer.get("image_sha256"),
                    "leaf_index": proof.get("leaf_index"),
                    "entry_hash": notarylib.leaf_hash(entry),
                },
            }
        )
        self._notary = self._load_notary()

    def _report_notary_evidence(self, kind: str, evidence: dict) -> None:
        """Durable, content-deduped misbehavior report. The idempotency key is
        derived from the material itself, so reconnect replays and repeated
        detections of the same material never create a second copy."""
        material = {"kind": kind, "model": self.facts["model"], "evidence": evidence}
        key = "nev-" + hashlib.sha256(
            trustlib.canonical_json(material)
        ).hexdigest()[:32]
        try:
            self.client.post(
                "/api/device/notary-evidence",
                headers=self._h(),
                json={"kind": kind, "evidence": evidence, "idempotency_key": key},
            )
        except Exception:
            pass  # never mask the original detection

    def _apply_root_chain(self, chain: list[dict]):
        """Validate every link of a root-rotation chain, then commit the new
        trust root atomically. Any failure (bad link, missing authorization,
        crash) leaves the previous trust state fully intact — fail closed."""
        try:
            new_trust = trustlib.apply_root_chain(self._trust, chain, now=self._now())
        except trustlib.TrustError as e:
            self._post_rejection(e.reason, e.detail, None)
            raise
        if new_trust is not None and (
            self._trust is None or new_trust.root_version != self._trust.root_version
        ):
            self._write_trust_atomic(new_trust)
            self._trust = new_trust

    # ----- block download with verified resume -----
    def _blob_path(self) -> Path:
        return self.workdir / f"{self._offer['image_sha256']}.bin"

    def _offer_release_meta(self) -> dict | None:
        return ((self._offer or {}).get("release") or {}).get("metadata")

    def _verified_blocks(self, manifest) -> dict[int, bytes]:
        path = self._blob_path()
        if not path.exists():
            return {}
        data = path.read_bytes()
        good: dict[int, bytes] = {}
        cs = manifest["chunk_size"]
        for ch in manifest["chunks"]:
            i, size = ch["index"], ch["size"]
            block = data[i * cs:i * cs + size]
            if len(block) == size and hashlib.sha256(block).hexdigest() == ch["sha256"]:
                good[i] = block
        return good

    def _persist(self, manifest, good: dict[int, bytes]):
        buf = bytearray(manifest["size"])
        cs = manifest["chunk_size"]
        for i, block in good.items():
            buf[i * cs:i * cs + len(block)] = block
        self._blob_path().write_bytes(bytes(buf))

    def download(self, *, fail_after_chunks: int | None = None):
        """Fetch every block not locally verified. `fail_after_chunks` simulates
        an intermittent link; calling download() again resumes from verified."""
        assert self._offer, "check_in first"
        manifest = self._offer

        good = self._verified_blocks(manifest)

        # Telemetry: safe to fire repeatedly (idempotent), even after a crash
        # before the FSM transition landed.
        self._event("download_started", {"resumed": bool(good)}, key="download_started")
        if self._offer["install_state"] == "assigned":
            # First bytes move / resume after crash before the transition:
            # the stable key makes assigned -> downloading exactly-once.
            self._event("downloading", {"resumed": bool(good)}, key="downloading")

        new_fetched = 0
        for ch in manifest["chunks"]:
            i = ch["index"]
            if i in good:
                continue
            if fail_after_chunks is not None and new_fetched >= fail_after_chunks:
                self._persist(manifest, good)
                raise ConnectionError(
                    f"simulated disconnect after {new_fetched} new chunk(s)"
                )
            r = self.client.get(
                f"/api/device/artifacts/{manifest['image_id']}/chunks/{i}",
                params={"assignment_id": manifest["assignment_id"]},
                headers=self._h(),
            )
            if r.status_code == 409:
                self._persist(manifest, good)
                return {"aborted": r.json().get("detail", "paused"), "verified_blocks": len(good)}
            r.raise_for_status()
            if hashlib.sha256(r.content).hexdigest() != ch["sha256"]:
                # A modified block is rejected before any critical write; the
                # receipt is durable and the retry re-fetches + re-reports.
                self._post_rejection(
                    trustlib.DIGEST_MISMATCH,
                    f"chunk {i} sha256 mismatch",
                    self._offer_release_meta(),
                )
                raise IOError(f"chunk {i} hash mismatch")
            good[i] = r.content
            new_fetched += 1
            if self._offer["install_state"] == "assigned":
                # First verified byte advances the FSM; stable key means a crash
                # between HTTP receipt and local bookkeeping stays replay-safe.
                self._event("downloading", {"resumed": bool(good) and i > 0}, key="downloading")
            self._persist(manifest, good)

        blob = b"".join(good[i] for i in sorted(good))
        if hashlib.sha256(blob).hexdigest() != manifest["image_sha256"]:
            self._post_rejection(
                trustlib.DIGEST_MISMATCH, "full image sha256 mismatch", self._offer_release_meta()
            )
            raise IOError("full image sha256 mismatch")

        if self._offer["install_state"] != "downloaded":
            self._event("downloaded", {"size": len(blob)})
        return {"aborted": None, "verified_blocks": len(good), "new_blocks": new_fetched}

    # ----- pre-flash validation gate -----
    def _validate_release_gate(self) -> dict:
        """Validate the signed release BEFORE the critical write phase: trust
        chain, signatures, expiry, artifact digest and security counter. Any
        failure leaves the active boot slot untouched and is reported as a
        durable, idempotent rejection receipt."""
        envelope = (self._offer or {}).get("release")
        meta = (envelope or {}).get("metadata")
        try:
            if envelope is None:
                raise trustlib.TrustError(
                    trustlib.MISSING_METADATA, "offer carries no signed release"
                )
            if self._trust is None:
                raise trustlib.TrustError(
                    trustlib.NO_TRUST_ROOT, "device holds no trust root"
                )
            meta = trustlib.validate_release(
                envelope,
                self._trust,
                device_model=self.facts["model"],
                artifact_sha256=self._offer["image_sha256"],
                now=self._now(),
            )
        except trustlib.TrustError as e:
            self._post_rejection(e.reason, e.detail, meta if isinstance(meta, dict) else None)
            raise
        # The accepted counter is the new floor: persist it BEFORE the first
        # critical write so a restart can never accept anything lower.
        counter = int(meta["security_counter"])
        if counter > self._trust.highest_counter:
            self._trust.highest_counter = counter
            self._write_trust_atomic(self._trust)
        return meta

    # ----- install / rollback -----
    def install(self) -> dict:
        assert self._offer and self._offer["install_state"] == "downloaded", "download first"
        self._validate_release_gate()  # fail closed before the critical region
        self._event("installing", {"slot": self._inactive_slot()})

        if self.fail_install:
            version = self.slots[self.active_slot]
            res = self._event(
                "failed",
                {"reason": "post-flash health check failed: sim", "rolled_back_to": version},
            )
            self._event("rollback_complete", {"rolled_back_to": version, "slot": self.active_slot})
            self._save_state()
            return {"result": "failed", "rolled_back_to": version, "halted": res.get("halted_batch_ids", [])}

        target_version = self._offer["version"]
        target_slot = self._inactive_slot()
        self.slots[target_slot] = target_version
        self.active_slot = target_slot
        self.facts["current_version"] = target_version
        self._save_state()
        self._event("installed", {"version": target_version, "slot": target_slot})
        return {"result": "installed", "version": target_version}

    def _inactive_slot(self) -> str:
        return "B" if self.active_slot == "A" else "A"

    # ----- end-to-end convenience -----
    def run_cycle(self, *, fail_after_chunks: int | None = None, resume: bool = True):
        self.register()
        body = self.check_in()
        if not body.get("offered"):
            return body
        try:
            self.download(fail_after_chunks=fail_after_chunks)
        except ConnectionError:
            if not resume:
                raise
            self.check_in()
            self.download()
        return self.install()
