"""ORM model.

Device assignment is the per-(device, campaign) rollout ledger row. Its
`install_state` is the single monotonically-progressing FSM variable that all
safety gates key off of; `device_events` is an append-only audit trail with an
idempotency key so duplicate receipts cannot double-count anything.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- device-side install FSM --------------------------------------------------
STATE_REGISTERED = "registered"        # only exists as a device
STATE_ASSIGNED = "assigned"            # seat claimed, nothing downloaded
STATE_DOWNLOADING = "downloading"
STATE_DOWNLOADED = "downloaded"
STATE_INSTALLING = "installing"        # critical region: flash writes started
STATE_INSTALLED = "installed"          # confirmed boot on new firmware
STATE_FAILED = "failed"                # install failed, device rolled back
STATE_ROLLED_BACK = "rolled_back"      # explicit rollback completion receipt

# Terminal states (no further offers for this campaign)
TERMINAL_STATES = frozenset({STATE_INSTALLED, STATE_FAILED})
# Past download gate: pause must not strand a device mid-flash.
PAST_DOWNLOAD_STATES = frozenset({STATE_DOWNLOADED, STATE_INSTALLING})
# Critical region: device must be allowed to finish / roll back safely.
CRITICAL_STATES = frozenset({STATE_INSTALLING})

# Forward-only transitions accepted from device receipts.
ALLOWED_TRANSITIONS: dict[str, frozenset[str, ...]] = {
    STATE_ASSIGNED: frozenset({STATE_DOWNLOADING}),
    STATE_DOWNLOADING: frozenset({STATE_DOWNLOADED, STATE_ASSIGNED}),
    STATE_DOWNLOADED: frozenset({STATE_INSTALLING}),
    STATE_INSTALLING: frozenset({STATE_INSTALLED, STATE_FAILED, STATE_ROLLED_BACK}),
}

# --- rollout batch lifecycle --------------------------------------------------
BATCH_PENDING = "pending"
BATCH_ACTIVE = "active"
BATCH_PAUSED = "paused"     # operator hold; resumable
BATCH_HALTED = "halted"     # auto stop or kill switch; resumable only explicitly
BATCH_COMPLETE = "complete"

BATCH_OPEN_STATES = frozenset({BATCH_ACTIVE})
BATCH_NON_TERMINAL = frozenset({BATCH_PENDING, BATCH_ACTIVE, BATCH_PAUSED, BATCH_HALTED})


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    hardware_batch: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    bootloader: Mapped[str] = mapped_column(String(64), nullable=False)
    current_version: Mapped[str] = mapped_column(String(64), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    assignments: Mapped[list["Assignment"]] = relationship(back_populates="device")


class Image(Base):
    __tablename__ = "images"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    min_bootloader: Mapped[str | None] = mapped_column(String(64), nullable=True)
    max_bootloader: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    chunk_size: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("model", "version", name="uq_image_model_version"),)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    image_id: Mapped[str] = mapped_column(ForeignKey("images.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    batches: Mapped[list["Batch"]] = relationship(back_populates="campaign")


class Batch(Base):
    """A staged rollout targeting one hardware batch. Children are the next
    stages; pausing/halting cascades through descendants so diffusion stops
    along the whole staged path."""
    __tablename__ = "batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False, index=True)
    hardware_batch: Mapped[str] = mapped_column(String(128), nullable=False)
    stage: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # quota_mode: 'absolute' -> quota seats; 'percent' -> % of fleet of the hw batch
    quota_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="absolute")
    quota_value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default=BATCH_PENDING)
    failure_threshold: Mapped[float] = mapped_column(Float, nullable=False)
    failure_min_sample: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("batches.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    campaign: Mapped[Campaign] = relationship(back_populates="batches")

    __table_args__ = (
        UniqueConstraint("campaign_id", "hardware_batch", "stage", name="uq_batch_campaign_hw_stage"),
        CheckConstraint("quota_mode in ('absolute','percent')", name="ck_batch_quota_mode"),
    )


class Assignment(Base):
    __tablename__ = "assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), nullable=False, index=True)
    install_state: Mapped[str] = mapped_column(String(16), nullable=False, default=STATE_ASSIGNED)
    offered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    fail_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    active_slot: Mapped[str] = mapped_column(String(16), nullable=False, default="A")

    device: Mapped[Device] = relationship(back_populates="assignments")

    __table_args__ = (
        UniqueConstraint("device_id", "campaign_id", name="uq_assignment_device_campaign"),
        Index("ix_assignment_batch_state", "batch_id", "install_state"),
    )


class DeviceEvent(Base):
    __tablename__ = "device_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    assignment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("device_id", "idempotency_key", name="uq_event_device_idem"),
    )


# --- offline release signing: versioned trust root + signed releases ---------
class RootMetadata(Base):
    """One link of the trust-root chain. Versions are consecutive integers;
    vN+1 is only stored after proving authorization by both the vN and the
    vN+1 root keys. The chain is the service's authoritative trust state and can
    never move backwards (rewrites/gaps are rejected at publish time)."""
    __tablename__ = "root_metadata"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False)      # canonical JSON
    signatures_json: Mapped[str] = mapped_column(Text, nullable=False)  # canonical JSON
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Release(Base):
    """A signed release bound 1:1 to an image. The canonical metadata +
    signatures are stored verbatim so devices re-verify offline; the columns
    mirror the signed fields for server-side gating and monotonicity checks."""
    __tablename__ = "releases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    image_id: Mapped[str] = mapped_column(ForeignKey("images.id"), nullable=False, unique=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    security_counter: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[str] = mapped_column(String(40), nullable=False)  # ISO-8601 UTC
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False)     # canonical JSON
    signatures_json: Mapped[str] = mapped_column(Text, nullable=False)   # canonical JSON
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("model", "version", name="uq_release_model_version"),
    )


# --- software-supply notarization: append-only Merkle ledger ----------------
class NotaryLeaf(Base):
    """One canonical ledger entry appended to the Merkle log. Leaves are
    append-only and never rewritten: the (entry) content hash is unique, and
    the request token that registered it is unique, so a retried registration
    can never create a second leaf."""
    __tablename__ = "notary_leaves"

    # 1-based tree position (0 would mean "empty tree").
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)       # root | release
    ref: Mapped[str] = mapped_column(String(64), nullable=False)        # root version / release id
    model: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_json: Mapped[str] = mapped_column(Text, nullable=False)       # canonical entry
    leaf_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    request_token: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotaryCheckpoint(Base):
    """A notary-key-signed checkpoint over the log. Canonical checkpoints are
    unique per tree size (one honest checkpoint per height); an ALTERNATE
    same-size checkpoint carrying a valid signature but a different root is
    evidence of equivocation and is retained — never replacing the canonical
    one — to drive the affected model(s) into quarantine."""
    __tablename__ = "notary_checkpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tree_size: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    root: Mapped[str] = mapped_column(String(64), nullable=False)
    checkpoint_json: Mapped[str] = mapped_column(Text, nullable=False)   # canonical cp body
    signatures_json: Mapped[str] = mapped_column(Text, nullable=False)   # canonical JSON
    canonical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("tree_size", "root", name="uq_notary_cp_size_root"),
    )


class QuarantinedModel(Base):
    """A model permanently placed under observation after notarization
    equivocation/tampering evidence. Survives process restarts (it is a
    regular durable table); new claims for the model are blocked while devices
    already in the flash critical region are allowed to finish."""
    __tablename__ = "quarantined_models"

    model: Mapped[str] = mapped_column(String(128), primary_key=True)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotarySuspicion(Base):
    """Durable, queryable evidence a node reported when a witness failed
    verification (tampered witness bytes, unlinkable history, tree shrink,
    same-height different-root). Deduplicated by the hash of the evidence
    itself: submitting the same material twice stores exactly one row."""
    __tablename__ = "notary_suspicions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)  # canonical evidence
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
