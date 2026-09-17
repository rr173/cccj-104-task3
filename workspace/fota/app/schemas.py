"""Pydantic v2 schemas for the HTTP API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ----- device side -----
class RegisterIn(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    model: str
    hardware_batch: str
    bootloader: str
    current_version: str


class ChunkOut(BaseModel):
    index: int
    sha256: str
    offset: int
    size: int


class Envelope(BaseModel):
    """A signed document: canonical-serializable metadata + detached sigs."""
    metadata: dict[str, Any]
    signatures: list[dict[str, str]]


class TrustBundle(BaseModel):
    """Root-chain links above the device's reported root version."""
    latest_root_version: int
    root_chain: list[Envelope] = Field(default_factory=list)


class OfferOut(BaseModel):
    assignment_id: str
    campaign_id: str
    batch_id: str
    image_id: str
    image_sha256: str
    version: str
    size: int
    chunk_size: int
    chunks: list[ChunkOut]
    finalize_only: bool
    install_state: str
    # Signed release envelope the device must validate before the critical
    # write phase (None only defensively — unsigned images are never offered).
    release: Envelope | None = None


class CheckInResponse(BaseModel):
    device_id: str
    offered: bool
    reason: str | None = None
    offer: OfferOut | None = None
    trust: TrustBundle | None = None
    server_time: datetime


class EventIn(BaseModel):
    # Optional only for telemetry receipts (e.g. release_rejected) that can
    # occur before/without an offer; FSM-moving events still require it.
    assignment_id: str | None = None
    event_type: str
    idempotency_key: str = Field(min_length=8, max_length=120)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    duplicate: bool
    applied: bool
    from_state: str | None = None
    to_state: str | None = None
    halted_batch_ids: list[str] = Field(default_factory=list)


# ----- admin side -----
class ImageOut(BaseModel):
    id: str
    model: str
    version: str
    min_bootloader: str | None
    max_bootloader: str | None
    size: int
    sha256: str
    chunk_size: int
    chunk_count: int
    created_at: datetime


class CampaignIn(BaseModel):
    name: str
    image_id: str


class CampaignOut(BaseModel):
    id: str
    name: str
    image_id: str
    created_at: datetime


class BatchIn(BaseModel):
    campaign_id: str
    hardware_batch: str
    stage: int = Field(ge=1, default=1)
    quota_mode: Literal["absolute", "percent"] = "absolute"
    quota_value: int = Field(ge=0, default=0)
    failure_threshold: float | None = Field(default=None, ge=0, le=1)
    failure_min_sample: int | None = Field(default=None, ge=1)
    parent_id: str | None = None


class BatchOut(BaseModel):
    id: str
    campaign_id: str
    hardware_batch: str
    stage: int
    quota_mode: str
    quota_value: int
    state: str
    failure_threshold: float
    failure_min_sample: int
    parent_id: str | None
    created_at: datetime
    stats: dict[str, Any] | None = None


class BatchActionIn(BaseModel):
    action: Literal["activate", "pause", "halt", "resume", "complete"]
    force: bool = False


# ----- offline signing: root chain + release publication -----
class RootPublishIn(BaseModel):
    metadata: dict[str, Any]
    signatures: list[dict[str, str]]
    idempotency_key: str = Field(min_length=8, max_length=120)


class ReleasePublishIn(BaseModel):
    # Optional cross-check; the release is bound to the image by digest.
    image_id: str | None = None
    metadata: dict[str, Any]
    signatures: list[dict[str, str]]
    idempotency_key: str = Field(min_length=8, max_length=120)


class DeviceOut(BaseModel):
    id: str
    model: str
    hardware_batch: str
    bootloader: str
    current_version: str
    last_seen: datetime
