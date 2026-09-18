"""Operator-facing API: images, campaigns, staged batches, fleet/debug views."""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config, notarization, publishing, rollout, storage
from ..db import get_session
from ..models import (
    Assignment,
    Batch,
    Campaign,
    Device,
    DeviceEvent,
    Image,
    NotaryCheckpoint,
    NotaryEvidence,
    NotaryLeaf,
    QuarantinedModel,
    Release,
    RootMetadata,
    utcnow,
)
from ..schemas import (
    BatchActionIn,
    BatchIn,
    BatchOut,
    CampaignIn,
    CampaignOut,
    DeviceOut,
    ImageOut,
    RegisterIn,
    ReleasePublishIn,
    RootPublishIn,
)

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _batch_out(db: Session, b: Batch) -> BatchOut:
    return BatchOut(
        id=b.id,
        campaign_id=b.campaign_id,
        hardware_batch=b.hardware_batch,
        stage=b.stage,
        quota_mode=b.quota_mode,
        quota_value=b.quota_value,
        state=b.state,
        failure_threshold=b.failure_threshold,
        failure_min_sample=b.failure_min_sample,
        parent_id=b.parent_id,
        created_at=b.created_at,
        stats=rollout.batch_stats(db, b.id),
    )


# ----- images -----
@router.post("/images", response_model=ImageOut, status_code=status.HTTP_201_CREATED)
async def upload_image(
    file: UploadFile = File(...),
    model: str = Form(...),
    version: str = Form(...),
    min_bootloader: str | None = Form(default=None),
    max_bootloader: str | None = Form(default=None),
    db: Session = Depends(get_session),
) -> ImageOut:
    data = await file.read()
    stored = storage.save_blob(data)
    existing = db.scalar(select(Image).where(Image.sha256 == stored.sha256))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"image_exists:{existing.id}")
    dup_v = db.scalar(select(Image).where(Image.model == model, Image.version == version))
    if dup_v is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "model_version_exists")
    img = Image(
        id=str(uuid.uuid4()),
        model=model,
        version=version,
        min_bootloader=min_bootloader,
        max_bootloader=max_bootloader,
        size=stored.size,
        sha256=stored.sha256,
        chunk_size=stored.chunk_size,
        chunk_count=stored.chunk_count,
    )
    db.add(img)
    db.commit()
    db.refresh(img)
    return img  # type: ignore[return-value]


@router.get("/images", response_model=list[ImageOut])
def list_images(db: Session = Depends(get_session)):
    return db.scalars(select(Image).order_by(Image.created_at.desc())).all()


# ----- offline signing: trust root chain -----
@router.post("/roots")
def publish_root(body: RootPublishIn, db: Session = Depends(get_session)):
    """Publish one root-chain link. v1 bootstraps (self-signed); vN+1 must be
    authorized by both the old and the new root keys. Idempotent by key."""
    try:
        return publishing.publish_root(
            db,
            metadata=body.metadata,
            signatures=body.signatures,
            idempotency_key=body.idempotency_key,
        )
    except publishing.NotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    except publishing.Conflict as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except publishing.Validation as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))


@router.get("/roots")
def list_roots(db: Session = Depends(get_session)):
    rows = db.scalars(select(RootMetadata).order_by(RootMetadata.version.asc())).all()
    return [
        {
            "version": r.version,
            "metadata": json.loads(r.metadata_json),
            "signatures": json.loads(r.signatures_json),
            "content_hash": r.content_hash,
            "created_at": r.created_at,
        }
        for r in rows
    ]


# ----- offline signing: releases -----
@router.post("/releases")
def publish_release(body: ReleasePublishIn, db: Session = Depends(get_session)):
    """Publish a signed release for an already-uploaded image. The service
    verifies the trust chain, signature, expiry, digest binding and counter
    monotonicity before anything is stored; idempotent by key."""
    try:
        return publishing.publish_release(
            db,
            image_id=body.image_id,
            metadata=body.metadata,
            signatures=body.signatures,
            idempotency_key=body.idempotency_key,
        )
    except publishing.NotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    except publishing.Conflict as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except publishing.Validation as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))


@router.get("/releases")
def list_releases(model: str | None = None, db: Session = Depends(get_session)):
    q = select(Release).order_by(Release.created_at.desc())
    if model:
        q = q.where(Release.model == model)
    return [
        {
            "id": r.id,
            "image_id": r.image_id,
            "model": r.model,
            "version": r.version,
            "artifact_sha256": r.artifact_sha256,
            "security_counter": r.security_counter,
            "expires_at": r.expires_at,
            "content_hash": r.content_hash,
            "created_at": r.created_at,
        }
        for r in db.scalars(q).all()
    ]


# ----- supply-chain notarization: ledger, evidence, quarantine -----
@router.get("/notary/info")
def notary_info(db: Session = Depends(get_session)):
    """Notary public key + current signed checkpoint."""
    info = notarization.notary_public_info()
    cp = notarization.current_checkpoint(db)
    return {
        **info,
        "tree_size": cp.tree_size if cp else 0,
        "root_hash": cp.root_hash if cp else None,
        "signature": cp.signature if cp else None,
    }


@router.get("/notary/tree")
def notary_tree(db: Session = Depends(get_session)):
    """Full ledger view for operators: every canonical leaf + every signed
    checkpoint. Devices never need this — their proofs are O(log n)."""
    leaves = db.scalars(select(NotaryLeaf).order_by(NotaryLeaf.leaf_index.asc())).all()
    checkpoints = db.scalars(
        select(NotaryCheckpoint).order_by(NotaryCheckpoint.tree_size.asc())
    ).all()
    return {
        "tree_size": len(leaves),
        "leaves": [
            {
                "leaf_index": l.leaf_index,
                "entry_type": l.entry_type,
                "ref_id": l.ref_id,
                "entry": json.loads(l.entry_json),
                "leaf_hash": l.leaf_hash,
                "created_at": l.created_at,
            }
            for l in leaves
        ],
        "checkpoints": [
            {
                "tree_size": c.tree_size,
                "root_hash": c.root_hash,
                "signature": c.signature,
                "created_at": c.created_at,
            }
            for c in checkpoints
        ],
    }


@router.get("/notary/evidence")
def notary_evidence(model: str | None = None, db: Session = Depends(get_session)):
    """Suspicious notary material reported by devices (content-deduped)."""
    q = select(NotaryEvidence).order_by(NotaryEvidence.id.asc())
    if model:
        q = q.where(NotaryEvidence.model == model)
    return [
        {
            "id": e.id,
            "evidence_hash": e.evidence_hash,
            "device_id": e.device_id,
            "model": e.model,
            "kind": e.kind,
            "evidence": json.loads(e.detail_json),
            "created_at": e.created_at,
        }
        for e in db.scalars(q).all()
    ]


@router.get("/notary/quarantine")
def notary_quarantine(db: Session = Depends(get_session)):
    """Models under permanent notary quarantine."""
    rows = db.scalars(select(QuarantinedModel).order_by(QuarantinedModel.created_at.asc())).all()
    return [
        {
            "model": r.model,
            "reason": r.reason,
            "evidence_hash": r.evidence_hash,
            "created_at": r.created_at,
        }
        for r in rows
    ]


# ----- campaigns -----
@router.post("/campaigns", response_model=CampaignOut, status_code=status.HTTP_201_CREATED)
def create_campaign(body: CampaignIn, db: Session = Depends(get_session)) -> CampaignOut:
    if db.get(Image, body.image_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "image_not_found")
    c = Campaign(id=str(uuid.uuid4()), name=body.name, image_id=body.image_id)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(db: Session = Depends(get_session)):
    return db.scalars(select(Campaign).order_by(Campaign.created_at.desc())).all()


# ----- batches (staged rollout) -----
@router.post("/batches", response_model=BatchOut, status_code=status.HTTP_201_CREATED)
def create_batch(body: BatchIn, db: Session = Depends(get_session)) -> BatchOut:
    if db.get(Campaign, body.campaign_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "campaign_not_found")
    if body.parent_id is not None and db.get(Batch, body.parent_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "parent_batch_not_found")
    dup = db.scalar(
        select(Batch).where(
            Batch.campaign_id == body.campaign_id,
            Batch.hardware_batch == body.hardware_batch,
            Batch.stage == body.stage,
        )
    )
    if dup is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "batch_stage_exists")
    b = Batch(
        id=str(uuid.uuid4()),
        campaign_id=body.campaign_id,
        hardware_batch=body.hardware_batch,
        stage=body.stage,
        quota_mode=body.quota_mode,
        quota_value=body.quota_value,
        failure_threshold=(
            body.failure_threshold
            if body.failure_threshold is not None
            else config.FAILURE_THRESHOLD
        ),
        failure_min_sample=(
            body.failure_min_sample
            if body.failure_min_sample is not None
            else config.FAILURE_MIN_SAMPLE
        ),
        parent_id=body.parent_id,
    )
    db.add(b)
    db.commit()
    db.refresh(b)
    return _batch_out(db, b)


@router.get("/batches", response_model=list[BatchOut])
def list_batches(campaign_id: str | None = None, db: Session = Depends(get_session)):
    q = select(Batch).order_by(Batch.stage.asc(), Batch.created_at.asc())
    if campaign_id:
        q = q.where(Batch.campaign_id == campaign_id)
    return [_batch_out(db, b) for b in db.scalars(q).all()]


@router.get("/batches/{batch_id}", response_model=BatchOut)
def get_batch(batch_id: str, db: Session = Depends(get_session)) -> BatchOut:
    b = db.get(Batch, batch_id)
    if b is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "batch_not_found")
    return _batch_out(db, b)


@router.post("/batches/{batch_id}/action", response_model=BatchOut)
def batch_action(
    batch_id: str, body: BatchActionIn, db: Session = Depends(get_session)
) -> BatchOut:
    try:
        b = rollout.set_batch_state(db, batch_id, body.action, force=body.force)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "batch_not_found")
    except PermissionError:
        raise HTTPException(status.HTTP_409_CONFLICT, "force_required_to_resume_halted")
    except rollout.StateError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad_action")
    return _batch_out(db, b)


# ----- fleet / debug -----
@router.post("/devices", response_model=DeviceOut)
def upsert_device(body: RegisterIn, db: Session = Depends(get_session)) -> DeviceOut:
    d = db.get(Device, body.id)
    if d is None:
        d = Device(id=body.id, last_seen=utcnow())
        db.add(d)
    d.model, d.hardware_batch, d.bootloader, d.current_version = (
        body.model,
        body.hardware_batch,
        body.bootloader,
        body.current_version,
    )
    db.commit()
    db.refresh(d)
    return d


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    hardware_batch: str | None = None,
    model: str | None = None,
    db: Session = Depends(get_session),
):
    q = select(Device)
    if hardware_batch:
        q = q.where(Device.hardware_batch == hardware_batch)
    if model:
        q = q.where(Device.model == model)
    return db.scalars(q.order_by(Device.id)).all()


@router.get("/assignments")
def list_assignments(batch_id: str | None = None, db: Session = Depends(get_session)):
    q = select(Assignment)
    if batch_id:
        q = q.where(Assignment.batch_id == batch_id)
    out = []
    for a in db.scalars(q.order_by(Assignment.offered_at)).all():
        out.append(
            {
                "id": a.id,
                "device_id": a.device_id,
                "batch_id": a.batch_id,
                "campaign_id": a.campaign_id,
                "install_state": a.install_state,
                "fail_reason": a.fail_reason,
                "active_slot": a.active_slot,
                "updated_at": a.updated_at,
            }
        )
    return out


@router.get("/events")
def all_events(
    batch_id: str | None = None,
    event_type: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_session),
):
    q = select(DeviceEvent).order_by(DeviceEvent.id.desc()).limit(min(limit, 1000))
    if batch_id:
        ids = select(Assignment.id).where(Assignment.batch_id == batch_id)
        q = q.where(DeviceEvent.assignment_id.in_(ids))
    if event_type:
        q = q.where(DeviceEvent.event_type == event_type)
    return [
        {
            "id": e.id,
            "device_id": e.device_id,
            "event_type": e.event_type,
            "idempotency_key": e.idempotency_key,
            "from_state": e.from_state,
            "to_state": e.to_state,
            "duplicate": e.duplicate,
            "payload": json.loads(e.payload or "{}"),
            "created_at": e.created_at,
        }
        for e in db.scalars(q).all()
    ]


@router.get("/overview")
def overview(db: Session = Depends(get_session)):
    return {
        "devices": int(db.scalar(select(func.count(Device.id))) or 0),
        "images": int(db.scalar(select(func.count(Image.id))) or 0),
        "campaigns": int(db.scalar(select(func.count(Campaign.id))) or 0),
        "batches": int(db.scalar(select(func.count(Batch.id))) or 0),
        "assignments": int(db.scalar(select(func.count(Assignment.id))) or 0),
        "server_time": utcnow(),
    }
