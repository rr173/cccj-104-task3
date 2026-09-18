"""Rollout core: check-in seat claims, receipt state machine, failure-gating.

Concurrency model
-----------------
* A single in-process lock serializes seat claims and receipt-driven batch
  transitions (one uvicorn worker; SQLite writers are serialized anyway).
* `(device_id, campaign_id)` UNIQUE on assignments and
  `(device_id, idempotency_key)` UNIQUE on device_events are the durable
  backstops: even under multiple workers/Postgres, duplicate online devices
  and replayed receipts can never double-occupy a seat or double-count stats.
"""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import notary_service, publishing
from .models import (
    ALLOWED_TRANSITIONS,
    BATCH_ACTIVE,
    BATCH_COMPLETE,
    BATCH_HALTED,
    BATCH_NON_TERMINAL,
    BATCH_PAUSED,
    CRITICAL_STATES,
    PAST_DOWNLOAD_STATES,
    STATE_ASSIGNED,
    STATE_DOWNLOADED,
    STATE_DOWNLOADING,
    STATE_FAILED,
    STATE_INSTALLED,
    STATE_INSTALLING,
    TERMINAL_STATES,
    Assignment,
    Batch,
    Campaign,
    Device,
    DeviceEvent,
    Image,
    utcnow,
)
from .versioning import compare, compatible_bootloader

# One lock per process. With multiple workers use Postgres + SELECT ... FOR UPDATE
# on the candidate batch row inside the same transaction.
_claim_lock = threading.RLock()

# check-in "why not offered" reasons, useful for fleet-side diagnostics
REASON_UP_TO_DATE = "up_to_date"
REASON_NO_CAMPAIGN = "no_campaign"
REASON_BATCH_PAUSED = "batch_paused"
REASON_BATCH_HALTED = "batch_halted"
REASON_QUOTA_FULL = "quota_full"
REASON_TERMINAL = "terminal"
REASON_NO_SIGNED_RELEASE = "no_signed_release"
REASON_MODEL_QUARANTINED = "model_quarantined"

# Device receipts that move the FSM (telemetry-only events have no state entry).
EVENT_TO_STATE: dict[str, str] = {
    STATE_DOWNLOADING: STATE_DOWNLOADING,
    STATE_DOWNLOADED: STATE_DOWNLOADED,
    STATE_INSTALLING: STATE_INSTALLING,
    STATE_INSTALLED: STATE_INSTALLED,
    STATE_FAILED: STATE_FAILED,
}
# `release_rejected` is the durable, idempotent failure receipt a device posts
# when signed metadata/content fails validation before the critical write
# phase. It never moves the FSM: the device keeps its seat and its boot slot.
TELEMETRY_EVENTS = frozenset({"download_started", "rollback_complete", "info", "release_rejected"})
KNOWN_EVENTS = frozenset(EVENT_TO_STATE) | TELEMETRY_EVENTS


class StateError(Exception):
    def __init__(self, old: str, new: str):
        super().__init__(f"illegal_transition:{old}->{new}")
        self.old = old
        self.new = new


class GateError(Exception):
    """Batch paused/halted blocks FSM advancement for non-critical devices."""

    def __init__(self, batch_state: str):
        super().__init__(f"batch_{batch_state}")
        self.batch_state = batch_state


@dataclass
class Offer:
    assignment_id: str
    campaign_id: str
    batch_id: str
    image_id: str
    image_sha256: str
    version: str
    size: int
    chunk_size: int
    chunks: list[dict] = field(default_factory=list)
    # Signed release envelope (canonical metadata + signatures). The device
    # MUST validate it against its trust store before the critical write phase.
    release: dict | None = None
    # True when the device is already in/through the critical region: the
    # client must finish the pending install and then report. Never abort.
    finalize_only: bool = False
    install_state: str = STATE_ASSIGNED
    # Supply-notarization witness bundle (membership + continuity). The node
    # verifies both before touching the standby partition.
    notary: dict | None = None


@dataclass
class CheckInResult:
    device: Device
    offer: Offer | None = None
    reason: str | None = None
    # Root-chain links the device needs to catch up to the service's current
    # trust root (always present, even when nothing is offered).
    trust: dict | None = None


# ----------------------------------------------------------------------------- #
# Compatibility
# ----------------------------------------------------------------------------- #
def image_fits(device: Device, image: Image) -> bool:
    if image.model != device.model:
        return False
    if compare(device.current_version, image.version) == 0:
        return False
    return compatible_bootloader(device.bootloader, image)


def _last_size(size: int, chunk_size: int, chunk_count: int, i: int) -> int:
    if i < chunk_count - 1:
        return chunk_size
    return size - i * chunk_size


def _manifest_chunks(image: Image) -> list[dict]:
    from . import storage

    m = storage.load_manifest(image.sha256)
    if m is None:
        return []
    return [
        {
            "index": i,
            "sha256": h,
            "offset": i * m.chunk_size,
            "size": _last_size(m.size, m.chunk_size, m.chunk_count, i),
        }
        for i, h in enumerate(m.chunk_sha)
    ]


def _make_offer(db: Session, device: Device, assignment: Assignment, image: Image,
                *, notary_old_size: int = 0) -> Offer:
    rel = publishing.release_for_image(db, image.id)
    notary_bundle = None
    if rel is not None:
        notary_bundle = notary_service.bundle_for_kind_ref(
            db, "release", rel.id, notary_old_size
        )
    return Offer(
        assignment_id=assignment.id,
        campaign_id=assignment.campaign_id,
        batch_id=assignment.batch_id,
        image_id=image.id,
        image_sha256=image.sha256,
        version=image.version,
        size=image.size,
        chunk_size=image.chunk_size,
        chunks=_manifest_chunks(image),
        # The signed release envelope travels with the offer; the device
        # re-verifies it offline before entering the critical write phase.
        release=publishing.release_envelope(rel) if rel is not None else None,
        finalize_only=assignment.install_state in PAST_DOWNLOAD_STATES,
        install_state=assignment.install_state,
        notary=notary_bundle,
    )


# ----------------------------------------------------------------------------- #
# Seats / quotas
# ----------------------------------------------------------------------------- #
def _fleet_size(db: Session, hardware_batch: str, model: str | None = None) -> int:
    q = select(func.count(Device.id)).where(Device.hardware_batch == hardware_batch)
    if model:
        q = q.where(Device.model == model)
    return int(db.scalar(q) or 0)


def _effective_quota(db: Session, batch: Batch, image: Image) -> int:
    if batch.quota_mode == "percent":
        fleet = _fleet_size(db, batch.hardware_batch, model=image.model)
        return fleet * batch.quota_value // 100
    return batch.quota_value


def _seats_used(db: Session, batch_id: str) -> int:
    """Every ledger row counts — installed, failed, in-flight. A failed device
    keeps its seat so flapping devices can never churn quota."""
    return int(
        db.scalar(select(func.count(Assignment.id)).where(Assignment.batch_id == batch_id)) or 0
    )


def _candidate_batches(db: Session, device: Device) -> list[tuple[Batch, Campaign, Image]]:
    rows = db.execute(
        select(Batch, Campaign, Image)
        .join(Campaign, Campaign.id == Batch.campaign_id)
        .join(Image, Image.id == Campaign.image_id)
        .where(Batch.hardware_batch == device.hardware_batch, Batch.state == BATCH_ACTIVE)
        .order_by(Batch.stage.asc(), Batch.created_at.asc())
    ).all()
    return [(b, c, img) for (b, c, img) in rows if image_fits(device, img)]


# ----------------------------------------------------------------------------- #
# Check-in
# ----------------------------------------------------------------------------- #
def check_in(
    db: Session,
    device: Device,
    device_root_version: int = 0,
    notary_old_size: int = 0,
) -> CheckInResult:
    # Serialize the whole read-modify-write: prevents two concurrent check-ins
    # of the same device from racing, and keeps per-process seat claims atomic.
    # The UNIQUE(device,campaign) constraint remains the durable backstop.
    with _claim_lock:
        device.last_seen = utcnow()
        db.add(device)

        # Root-chain links above the device's reported root version: a device
        # that slept through several rotations catches up in one wake-up. The
        # bundle rides along on every check-in, offered or not.
        trust = publishing.trust_bundle(db, max(0, device_root_version))

        # Existing ledger rows for this device get first say (pause/finish safety).
        existing = db.scalars(
            select(Assignment)
            .where(Assignment.device_id == device.id)
            .order_by(Assignment.updated_at.desc())
        ).all()

        for asg in existing:
            if asg.install_state in TERMINAL_STATES:
                continue  # campaign done for this device
            batch = db.get(Batch, asg.batch_id)
            image = db.get(Image, db.get(Campaign, asg.campaign_id).image_id)

            if asg.install_state in CRITICAL_STATES:
                # Flash writes in progress: always allow finishing + reporting.
                # The notarization quarantine must not strand a node mid-flash.
                db.commit()
                return CheckInResult(
                    device,
                    _make_offer(db, device, asg, image, notary_old_size=notary_old_size),
                    trust=trust,
                )
            if notary_service.is_quarantined(db, image.model):
                # Observation zone: a node that never touched the standby
                # partition must stop; the active partition stays bootable.
                db.commit()
                return CheckInResult(device, None, REASON_MODEL_QUARANTINED, trust=trust)
            if batch.state == BATCH_PAUSED:
                db.commit()
                return CheckInResult(device, None, REASON_BATCH_PAUSED, trust=trust)
            if batch.state == BATCH_HALTED:
                db.commit()
                return CheckInResult(device, None, REASON_BATCH_HALTED, trust=trust)
            if batch.state == BATCH_ACTIVE:
                # assigned/downloading/downloaded: serve manifest so the client
                # resumes verified blocks or proceeds to install.
                db.commit()
                return CheckInResult(
                    device,
                    _make_offer(db, device, asg, image, notary_old_size=notary_old_size),
                    trust=trust,
                )

        # No live assignment: claim a seat in an active batch.
        return _claim_new(db, device, trust, notary_old_size)


def _claim_new(db: Session, device: Device, trust: dict, notary_old_size: int = 0) -> CheckInResult:
    if notary_service.is_quarantined(db, device.model):
        # New claims from a quarantined model are blocked fleet-wide.
        db.commit()
        return CheckInResult(device, None, REASON_MODEL_QUARANTINED, trust=trust)
    candidates = _candidate_batches(db, device)
    if not candidates:
        db.commit()
        return CheckInResult(device, None, REASON_NO_CAMPAIGN, trust=trust)

    now = datetime.now(timezone.utc)
    saw_unsigned = False
    for batch, _campaign, image in candidates:
        rel = publishing.release_for_image(db, image.id)
        if not publishing.release_currently_valid(rel, now):
            # Fail closed: an image without a valid signed release is never
            # offered, even if a compatible campaign is active.
            saw_unsigned = True
            continue
        b = db.get(Batch, batch.id)  # re-read under the lock
        if b.state != BATCH_ACTIVE:
            continue
        quota = _effective_quota(db, b, image)
        if _seats_used(db, b.id) >= quota:
            continue
        asg = Assignment(
            id=str(uuid.uuid4()),
            device_id=device.id,
            campaign_id=b.campaign_id,
            batch_id=b.id,
            install_state=STATE_ASSIGNED,
        )
        db.add(asg)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return CheckInResult(device, None, REASON_QUOTA_FULL, trust=trust)
        db.refresh(asg)
        return CheckInResult(
            device,
            _make_offer(db, device, asg, image, notary_old_size=notary_old_size),
            trust=trust,
        )

    db.commit()
    reason = REASON_NO_SIGNED_RELEASE if saw_unsigned else REASON_QUOTA_FULL
    return CheckInResult(device, None, reason, trust=trust)


# ----------------------------------------------------------------------------- #
# Artifact access gate
# ----------------------------------------------------------------------------- #
def authorize_chunk(
    db: Session, device_id: str, assignment_id: str
) -> tuple[Assignment | None, Image | None, str | None]:
    asg = db.get(Assignment, assignment_id)
    if asg is None or asg.device_id != device_id:
        return None, None, "not_found"
    if asg.install_state in TERMINAL_STATES:
        return asg, None, "terminal"
    campaign = db.get(Campaign, asg.campaign_id)
    image = db.get(Image, campaign.image_id)
    batch = db.get(Batch, asg.batch_id)
    if asg.install_state in CRITICAL_STATES:
        return asg, image, None  # critical-region finish path stays open
    if notary_service.is_quarantined(db, image.model):
        # Quarantine closes the path before any standby-partition write for
        # devices that have not started flashing.
        return asg, None, "model_quarantined"
    if batch.state == BATCH_PAUSED:
        return asg, None, "batch_paused"
    if batch.state == BATCH_HALTED:
        return asg, None, "batch_halted"
    return asg, image, None


# ----------------------------------------------------------------------------- #
# Receipts: idempotency + forward-only FSM + failure gating
# ----------------------------------------------------------------------------- #
def record_event(
    db: Session,
    *,
    device_id: str,
    assignment_id: str | None,
    event_type: str,
    idempotency_key: str,
    payload: dict | None = None,
) -> dict:
    """Apply a device receipt.

    A repeated (device_id, idempotency_key) returns the original outcome with
    duplicate=True and performs zero side effects — no state bump, no quota
    churn, no failure-rate recount.

    Telemetry receipts (e.g. `release_rejected`) may arrive without an
    assignment: a device that fails trust validation before/without an offer
    must still be able to leave its durable, idempotent failure receipt.
    """
    if event_type not in KNOWN_EVENTS:
        raise ValueError(f"unknown_event:{event_type}")

    with _claim_lock:
        dup = db.scalar(
            select(DeviceEvent).where(
                DeviceEvent.device_id == device_id,
                DeviceEvent.idempotency_key == idempotency_key,
            )
        )
        if dup is not None:
            return {
                "duplicate": True,
                "applied": not dup.duplicate,
                "from_state": dup.from_state,
                "to_state": dup.to_state,
                "event_type": dup.event_type,
                "halted_batch_ids": [],
            }

        asg = None
        if assignment_id is not None:
            asg = db.get(Assignment, assignment_id)
            if asg is None or asg.device_id != device_id:
                raise LookupError("assignment_not_found")
        elif event_type not in TELEMETRY_EVENTS:
            raise ValueError("assignment_required")

        old_state = asg.install_state if asg is not None else None
        new_state = EVENT_TO_STATE.get(event_type)
        if (
            asg is not None
            and new_state is not None
            and new_state not in ALLOWED_TRANSITIONS.get(old_state, frozenset())
        ):
            raise StateError(old_state, new_state)

        # Pause/halt gate: a device that has not entered the flash critical
        # region must not advance; an installing device is allowed to report
        # installed/failed so it can finish or roll back safely.
        if asg is not None and new_state is not None:
            batch = db.get(Batch, asg.batch_id)
            if (
                old_state not in CRITICAL_STATES
                and batch.state in (BATCH_PAUSED, BATCH_HALTED)
            ):
                raise GateError(batch.state)
            asg.install_state = new_state
            asg.updated_at = utcnow()

        device = db.get(Device, device_id)
        if asg is not None and event_type == STATE_FAILED:
            asg.fail_reason = str((payload or {}).get("reason", ""))[:4000]
            if device is not None and (payload or {}).get("rolled_back_to"):
                device.current_version = str(payload["rolled_back_to"])
        elif asg is not None and event_type == STATE_INSTALLED:
            if device is not None and (payload or {}).get("version"):
                device.current_version = str(payload["version"])
        elif event_type == "rollback_complete":
            if device is not None and (payload or {}).get("rolled_back_to"):
                device.current_version = str(payload["rolled_back_to"])

        evt = DeviceEvent(
            device_id=device_id,
            assignment_id=asg.id if asg is not None else None,
            event_type=event_type,
            idempotency_key=idempotency_key,
            from_state=old_state,
            to_state=new_state,
            payload=json.dumps(payload or {}, ensure_ascii=False),
            duplicate=False,
        )
        db.add(evt)

        halted: list[str] = []
        if asg is not None and new_state in (STATE_INSTALLED, STATE_FAILED):
            # batch.state may have been changed by another request/session;
            # refresh just that row so the halt decision cannot run on a stale
            # identity-map copy while this device was downloading.
            current_batch = db.get(Batch, asg.batch_id)
            db.refresh(current_batch)
            halted = _maybe_halt(db, current_batch)

        db.commit()
        return {
            "duplicate": False,
            "applied": True,
            "from_state": old_state,
            "to_state": new_state,
            "halted_batch_ids": halted,
        }


# ----------------------------------------------------------------------------- #
# Failure-driven auto halt
# ----------------------------------------------------------------------------- #
def batch_stats(db: Session, batch_id: str) -> dict:
    rows = db.execute(
        select(Assignment.install_state, func.count(Assignment.id))
        .where(Assignment.batch_id == batch_id)
        .group_by(Assignment.install_state)
    ).all()
    by_state = {s: n for s, n in rows}
    attempts = by_state.get(STATE_INSTALLED, 0) + by_state.get(STATE_FAILED, 0)
    failures = by_state.get(STATE_FAILED, 0)
    rate = failures / attempts if attempts else 0.0
    return {
        "seats": sum(by_state.values()),
        "installed": by_state.get(STATE_INSTALLED, 0),
        "failed": failures,
        "attempts": attempts,
        "failure_rate": rate,
        "by_state": by_state,
    }


def _maybe_halt(db: Session, batch: Batch | None) -> list[str]:
    """Halt an active batch that crossed its failure threshold and cascade to
    every non-terminal descendant stage so staged diffusion stops."""
    if batch is None or batch.state != BATCH_ACTIVE:
        return []
    db.flush()  # make this receipt's state visible to the stats query
    stats = batch_stats(db, batch.id)
    if stats["attempts"] < batch.failure_min_sample:
        return []
    if stats["failure_rate"] < batch.failure_threshold:
        return []

    halted: list[str] = []
    frontier = [batch.id]
    while frontier:
        b = db.get(Batch, frontier.pop())
        if b is None:
            continue
        if b.state in BATCH_NON_TERMINAL and b.state != BATCH_HALTED:
            b.state = BATCH_HALTED
            halted.append(b.id)
        frontier.extend(db.scalars(select(Batch.id).where(Batch.parent_id == b.id)).all())
    return halted


# ----------------------------------------------------------------------------- #
# Operator batch actions
# ----------------------------------------------------------------------------- #
def set_batch_state(
    db: Session, batch_id: str, action: str, *, force: bool = False
) -> Batch:
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise LookupError("batch_not_found")
    target = {
        "activate": BATCH_ACTIVE,
        "pause": BATCH_PAUSED,
        "halt": BATCH_HALTED,
        "resume": BATCH_ACTIVE,
        "complete": BATCH_COMPLETE,
    }.get(action)
    if target is None:
        raise ValueError("bad_action")
    if action == "resume" and batch.state == BATCH_HALTED and not force:
        raise PermissionError("force_required_to_resume_halted")
    if action in ("activate", "resume") and batch.state == BATCH_COMPLETE:
        raise StateError(batch.state, target)
    if action == "pause" and batch.state != BATCH_ACTIVE:
        raise StateError(batch.state, target)
    if action == "halt" and batch.state not in (BATCH_ACTIVE, BATCH_PAUSED):
        raise StateError(batch.state, target)

    batch.state = target
    # Operator stop-the-bleed actions cascade down staged descendants so no
    # later stage keeps handing out seats. Activate/resume are intentionally
    # local: later stages stay gated until explicitly enabled.
    if action in ("pause", "halt"):
        _cascade_state(db, batch.id, target)
    db.commit()
    db.refresh(batch)
    return batch


def _cascade_state(db: Session, root_id: str, target: str) -> None:
    frontier = [root_id]
    while frontier:
        pid = frontier.pop()
        children = db.scalars(select(Batch).where(Batch.parent_id == pid)).all()
        for ch in children:
            if ch.state in BATCH_NON_TERMINAL and ch.state != BATCH_HALTED:
                ch.state = target
            frontier.append(ch.id)
