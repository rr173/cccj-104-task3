"""Device-facing API: register, check-in, block download, receipts."""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import notarization, rollout, storage
from ..db import get_session
from ..models import Device, DeviceEvent, utcnow
from ..schemas import (
    CheckInResponse,
    EventIn,
    EventOut,
    NotaryEvidenceIn,
    OfferOut,
    RegisterIn,
    TrustBundle,
)

router = APIRouter(prefix="/api/device", tags=["device"])


def _device_or_404(db: Session, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device_not_registered")
    return d


def _device_id_header(x_device_id: str | None) -> str:
    if not x_device_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-Device-Id header required")
    return x_device_id


@router.post("/register", response_model=RegisterIn)
def register(body: RegisterIn, db: Session = Depends(get_session)) -> RegisterIn:
    """Idempotent self-registration / upsert of device facts."""
    d = db.get(Device, body.id)
    if d is None:
        d = Device(id=body.id, last_seen=utcnow())
        db.add(d)
    d.model = body.model
    d.hardware_batch = body.hardware_batch
    d.bootloader = body.bootloader
    d.current_version = body.current_version
    d.last_seen = utcnow()
    db.commit()
    return body


@router.post("/check-in", response_model=CheckInResponse)
def check_in(
    db: Session = Depends(get_session),
    x_device_id: str | None = Header(default=None),
    x_root_version: int | None = Header(default=None),
    x_notary_tree_size: int | None = Header(default=None),
) -> CheckInResponse:
    device = _device_or_404(db, _device_id_header(x_device_id))
    # The device reports the root version it currently trusts and the notary
    # checkpoint it last verified; the service returns the chain links and the
    # log-sized consistency path above them so the device catches up atomically.
    result = rollout.check_in(
        db,
        device,
        device_root_version=x_root_version or 0,
        device_tree_size=max(0, x_notary_tree_size or 0),
    )
    return CheckInResult_to_response(device, result)


def CheckInResult_to_response(device, result) -> CheckInResponse:  # noqa: N802
    offer = OfferOut(**result.offer.__dict__) if result.offer else None
    trust = TrustBundle(**result.trust) if result.trust else None
    return CheckInResponse(
        device_id=device.id,
        offered=result.offer is not None,
        reason=result.reason,
        offer=offer,
        trust=trust,
        notary=notarization.notary_public_info(),
        server_time=utcnow(),
    )


@router.get("/artifacts/{image_id}/chunks/{index}")
def get_chunk(
    image_id: str,
    index: int,
    assignment_id: str = Query(...),
    db: Session = Depends(get_session),
    x_device_id: str | None = Header(default=None),
):
    """One verified block. Clients re-request blocks whose local sha256 does
    not match the manifest, which makes interrupted downloads resumable."""
    device_id = _device_id_header(x_device_id)
    _device_or_404(db, device_id)
    _asg, image, gate = rollout.authorize_chunk(db, device_id, assignment_id)
    if gate == "not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assignment_not_found")
    if gate in ("batch_paused", "batch_halted", "model_quarantined"):
        raise HTTPException(status.HTTP_409_CONFLICT, gate)
    if gate == "terminal" or image is None or image.id != image_id:
        raise HTTPException(status.HTTP_410_GONE, "no_longer_available")
    block = storage.read_chunk(image.sha256, index)
    if block is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "chunk_not_found")
    return Response(
        content=block,
        media_type="application/octet-stream",
        headers={
            "X-Chunk-Sha256": hashlib.sha256(block).hexdigest(),
            "X-Image-Sha256": image.sha256,
            "Cache-Control": "private, max-age=31536000, immutable",
        },
    )


@router.post("/events", response_model=EventOut)
def post_event(
    body: EventIn,
    db: Session = Depends(get_session),
    x_device_id: str | None = Header(default=None),
) -> EventOut:
    device_id = _device_id_header(x_device_id)
    _device_or_404(db, device_id)
    try:
        out = rollout.record_event(
            db,
            device_id=device_id,
            assignment_id=body.assignment_id,
            event_type=body.event_type,
            idempotency_key=body.idempotency_key,
            payload=body.payload,
        )
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assignment_not_found")
    except rollout.QuarantineError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except rollout.GateError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except rollout.StateError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return EventOut(**out)


@router.post("/notary-evidence")
def post_notary_evidence(
    body: NotaryEvidenceIn,
    db: Session = Depends(get_session),
    x_device_id: str | None = Header(default=None),
):
    """A verifying device reports notary misbehavior (split-view checkpoint,
    shrunk tree, broken consistency, tampered membership proof). The material
    is stored once per distinct content and the device's model is quarantined
    permanently; reporting is always allowed, even for quarantined models."""
    device = _device_or_404(db, _device_id_header(x_device_id))
    try:
        return notarization.record_evidence(
            db,
            device_id=device.id,
            model=device.model,
            kind=body.kind,
            evidence=body.evidence,
            idempotency_key=body.idempotency_key,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.get("/events")
def list_events(
    db: Session = Depends(get_session),
    x_device_id: str | None = Header(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    device_id = _device_id_header(x_device_id)
    _device_or_404(db, device_id)
    rows = db.scalars(
        select(DeviceEvent)
        .where(DeviceEvent.device_id == device_id)
        .order_by(DeviceEvent.id.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "idempotency_key": e.idempotency_key,
            "from_state": e.from_state,
            "to_state": e.to_state,
            "duplicate": e.duplicate,
            "payload": json.loads(e.payload or "{}"),
            "created_at": e.created_at,
        }
        for e in rows
    ]
