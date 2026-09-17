"""Server-side publication of trust roots and signed releases.

Trust-state monotonicity (the service can never lower its own trust state):
* root versions must be exactly current+1 — rewrites, rollbacks and gaps are
  rejected before anything is stored;
* a release's security counter must not regress below the highest counter
  already published for that model;
* (model, version) releases are unique — different content claiming an already
  published release version conflicts.

Idempotency: every publish carries an idempotency key. A replay with identical
content returns the stored result (duplicate=True); the same key with
different content conflicts. The process lock serializes check-then-insert;
the UNIQUE constraints are the durable backstop under multiple workers.
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import trust as trustlib
from .models import Image, Release, RootMetadata

_publish_lock = threading.RLock()


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


class Validation(Exception):
    """Envelope is well-formed JSON but fails trust validation (-> 422)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Read side
# --------------------------------------------------------------------------- #
def current_root(db: Session) -> RootMetadata | None:
    return db.scalar(select(RootMetadata).order_by(RootMetadata.version.desc()).limit(1))


def _server_trust(row: RootMetadata | None) -> trustlib.TrustStore | None:
    if row is None:
        return None
    return trustlib.TrustStore(row.version, json.loads(row.metadata_json), 0)


def trust_bundle(db: Session, device_root_version: int) -> dict:
    """The chain links a device at `device_root_version` needs to catch up to
    the service's current root (empty when the device is current)."""
    rows = db.scalars(select(RootMetadata).order_by(RootMetadata.version.asc())).all()
    latest = rows[-1].version if rows else 0
    chain = [
        {"metadata": json.loads(r.metadata_json), "signatures": json.loads(r.signatures_json)}
        for r in rows
        if r.version > device_root_version
    ]
    return {"latest_root_version": latest, "root_chain": chain}


def release_for_image(db: Session, image_id: str) -> Release | None:
    return db.scalar(select(Release).where(Release.image_id == image_id))


def release_currently_valid(rel: Release | None, now: datetime) -> bool:
    if rel is None:
        return False
    try:
        return not trustlib.is_expired(rel.expires_at, now)
    except Exception:
        return False


def release_envelope(rel: Release) -> dict:
    return {
        "metadata": json.loads(rel.metadata_json),
        "signatures": json.loads(rel.signatures_json),
    }


# --------------------------------------------------------------------------- #
# Root chain publication
# --------------------------------------------------------------------------- #
def _root_out(row: RootMetadata, *, duplicate: bool) -> dict:
    return {
        "version": row.version,
        "metadata": json.loads(row.metadata_json),
        "signatures": json.loads(row.signatures_json),
        "content_hash": row.content_hash,
        "idempotency_key": row.idempotency_key,
        "duplicate": duplicate,
        "created_at": row.created_at.isoformat(),
    }


def publish_root(db: Session, *, metadata: dict, signatures: list, idempotency_key: str) -> dict:
    chash = trustlib.envelope_hash(metadata, signatures)
    with _publish_lock:
        dup = db.scalar(
            select(RootMetadata).where(RootMetadata.idempotency_key == idempotency_key)
        )
        if dup is not None:
            if dup.content_hash != chash:
                raise Conflict("idempotency_key_conflict")
            return _root_out(dup, duplicate=True)

        cur = current_root(db)
        try:
            version = int((metadata or {}).get("version"))
        except (TypeError, ValueError):
            raise Validation("malformed_root_metadata")
        if cur is not None and version <= cur.version:
            # Trust state never goes backwards: no rewrites, no rollbacks.
            raise Conflict("root_version_conflict")
        try:
            trustlib.validate_root_link(
                _server_trust(cur),
                {"metadata": metadata, "signatures": signatures},
                _now(),
            )
        except trustlib.TrustError as e:
            raise Validation(str(e))

        row = RootMetadata(
            version=version,
            metadata_json=trustlib.canonical_str(metadata),
            signatures_json=trustlib.canonical_str(trustlib.normalize_signatures(signatures)),
            content_hash=chash,
            idempotency_key=idempotency_key,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            row = db.scalar(
                select(RootMetadata).where(RootMetadata.idempotency_key == idempotency_key)
            )
            if row is not None and row.content_hash == chash:
                return _root_out(row, duplicate=True)
            raise Conflict("root_version_conflict")
        return _root_out(row, duplicate=False)


# --------------------------------------------------------------------------- #
# Release publication
# --------------------------------------------------------------------------- #
def _release_out(row: Release, *, duplicate: bool) -> dict:
    return {
        "id": row.id,
        "image_id": row.image_id,
        "model": row.model,
        "version": row.version,
        "artifact_sha256": row.artifact_sha256,
        "security_counter": row.security_counter,
        "expires_at": row.expires_at,
        "metadata": json.loads(row.metadata_json),
        "signatures": json.loads(row.signatures_json),
        "content_hash": row.content_hash,
        "idempotency_key": row.idempotency_key,
        "duplicate": duplicate,
        "created_at": row.created_at.isoformat(),
    }


def publish_release(
    db: Session,
    *,
    image_id: str | None,
    metadata: dict,
    signatures: list,
    idempotency_key: str,
) -> dict:
    chash = trustlib.envelope_hash(metadata, signatures)
    with _publish_lock:
        dup = db.scalar(select(Release).where(Release.idempotency_key == idempotency_key))
        if dup is not None:
            if dup.content_hash != chash:
                raise Conflict("idempotency_key_conflict")
            return _release_out(dup, duplicate=True)

        if not isinstance(metadata, dict) or metadata.get("type") != "release":
            raise Validation("malformed_release_metadata")
        digest = metadata.get("artifact_sha256")
        image = db.scalar(select(Image).where(Image.sha256 == digest)) if digest else None
        if image is None:
            raise NotFound("image_not_found_for_digest")
        if image_id is not None and image_id != image.id:
            raise Validation("image_digest_mismatch")
        if metadata.get("model") != image.model or metadata.get("version") != image.version:
            raise Validation("metadata_image_mismatch")

        for_image = db.scalar(select(Release).where(Release.image_id == image.id))
        if for_image is not None:
            if for_image.content_hash == chash:
                return _release_out(for_image, duplicate=True)
            raise Conflict("release_exists")
        same_version = db.scalar(
            select(Release).where(Release.model == image.model, Release.version == image.version)
        )
        if same_version is not None:
            # Different content claiming an already-published release version.
            raise Conflict("release_version_conflict")

        cur = current_root(db)
        if cur is None:
            raise Conflict("no_trust_root")
        try:
            trustlib.validate_release(
                {"metadata": metadata, "signatures": signatures},
                _server_trust(cur),
                device_model=image.model,
                artifact_sha256=image.sha256,
                now=_now(),
            )
        except trustlib.TrustError as e:
            raise Validation(str(e))

        try:
            counter = int(metadata.get("security_counter"))
        except (TypeError, ValueError):
            raise Validation("bad_security_counter")
        max_counter = db.scalar(
            select(func.max(Release.security_counter)).where(Release.model == image.model)
        )
        if max_counter is not None and counter < max_counter:
            # The published counter sequence is monotonic per model.
            raise Conflict("counter_regression")

        row = Release(
            id=str(uuid.uuid4()),
            image_id=image.id,
            model=image.model,
            version=image.version,
            artifact_sha256=image.sha256,
            security_counter=counter,
            expires_at=str(metadata.get("expires") or ""),
            metadata_json=trustlib.canonical_str(metadata),
            signatures_json=trustlib.canonical_str(trustlib.normalize_signatures(signatures)),
            content_hash=chash,
            idempotency_key=idempotency_key,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            row = db.scalar(select(Release).where(Release.idempotency_key == idempotency_key))
            if row is not None and row.content_hash == chash:
                return _release_out(row, duplicate=True)
            raise Conflict("release_version_conflict")
        return _release_out(row, duplicate=False)
