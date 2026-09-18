"""Server-side notarization ledger: append, checkpoint, prove, quarantine.

The ledger is an append-only Merkle tree (see `app/notary.py` for the math).
Every publication of a trust-root link or a signed release appends ONE leaf
and ONE signed checkpoint INSIDE the publication's own database transaction,
so the externally visible states are only ever:

* nothing published (crash before commit) — a retry with the same request
  token simply re-runs the whole append; or
* business row + leaf + signed checkpoint, together.

There is no interleaving in which an artifact is fetchable while the ledger
has no record of it, and a retried request yields at most one row and one
leaf. The process lock serializes index allocation; the leaf-index primary
key is the durable backstop under multiple workers (production: take the next
index with SELECT ... FOR UPDATE on a counter row, same place as the seat
claim note in rollout.py).

Proofs are computed from the stored leaf hashes on demand — O(n) hashing per
proof, O(log n) hashes on the wire. At ledger scale this is the right
trade-off for a reference implementation; production would cache subtree
tiles (the leaf table already contains everything needed to rebuild them).
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import config
from . import notary as notarylib
from . import trust as trustlib
from .models import NotaryCheckpoint, NotaryEvidence, NotaryLeaf, QuarantinedModel

_lock = threading.RLock()
_key_cache: dict | None = None


# --------------------------------------------------------------------------- #
# Notary key (ed25519). Generated once, persisted next to the DB; the public
# half is served to devices, which pin it (TOFU). Production: HSM/KMS.
# --------------------------------------------------------------------------- #
def _load_or_create_key() -> dict:
    global _key_cache
    with _lock:
        if _key_cache is not None:
            return _key_cache
        path = Path(config.NOTARY_KEY_PATH)
        if path.exists():
            _key_cache = json.loads(path.read_text())
            return _key_cache
        priv, pub = trustlib.generate_keypair()
        _key_cache = {"private": priv, "public": pub}
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(_key_cache))
        tmp.replace(path)  # atomic: a crash never leaves a half-written key
        return _key_cache


def notary_public_info() -> dict:
    """The key identity devices pin and verify checkpoints against."""
    key = _load_or_create_key()
    return {"key_id": trustlib.key_id(key["public"]), "public_key": key["public"]}


# --------------------------------------------------------------------------- #
# Append (called INSIDE the publisher's transaction)
# --------------------------------------------------------------------------- #
def release_entry(release_row) -> dict:
    """Canonical ledger entry for a signed release (binds the artifact digest
    and the release envelope hash the device re-computes from the offer)."""
    return {
        "entry": "release",
        "content_hash": release_row.content_hash,
        "model": release_row.model,
        "version": release_row.version,
        "artifact_sha256": release_row.artifact_sha256,
    }


def root_entry(version: int, content_hash: str) -> dict:
    """Canonical ledger entry for a trust-root handoff."""
    return {"entry": "root", "version": int(version), "content_hash": content_hash}


def append_entry(db: Session, entry_type: str, ref_id: str, entry: dict) -> NotaryLeaf:
    """Append one canonical entry to the tree tail and sign the new checkpoint.

    Must be called with the publication row already staged in the same session
    and BEFORE the shared commit: the leaf, the checkpoint and the business
    row become visible atomically (or not at all).
    """
    with _lock:
        max_index = db.scalar(select(func.max(NotaryLeaf.leaf_index)))
        next_index = (max_index + 1) if max_index is not None else 0
        leaf = NotaryLeaf(
            leaf_index=next_index,
            entry_type=entry_type,
            ref_id=str(ref_id),
            entry_json=trustlib.canonical_str(entry),
            leaf_hash=notarylib.leaf_hash(entry),
        )
        db.add(leaf)
        db.flush()  # leaf_index PK conflict surfaces here, inside the tx

        leaves = _leaf_hashes(db)
        size = len(leaves)
        root = notarylib.mth(leaves)
        checkpoint = NotaryCheckpoint(
            tree_size=size,
            root_hash=root,
            signature=notarylib.sign_checkpoint(size, root, _load_or_create_key()["private"]),
        )
        db.add(checkpoint)
        db.flush()
        return leaf


# --------------------------------------------------------------------------- #
# Read side / proof materialization
# --------------------------------------------------------------------------- #
def _leaf_hashes(db: Session) -> list[str]:
    return list(db.scalars(select(NotaryLeaf.leaf_hash).order_by(NotaryLeaf.leaf_index.asc())).all())


def current_checkpoint(db: Session) -> NotaryCheckpoint | None:
    return db.scalar(
        select(NotaryCheckpoint).order_by(NotaryCheckpoint.tree_size.desc()).limit(1)
    )


def checkpoint_dict(row: NotaryCheckpoint) -> dict:
    return {"tree_size": row.tree_size, "root_hash": row.root_hash, "signature": row.signature}


def _proof_bundle(db: Session, leaf: NotaryLeaf, since_size: int) -> dict | None:
    """Inclusion path for `leaf` + consistency path from the device's stored
    checkpoint (`since_size`) to the current one. Both are O(log n) hashes."""
    checkpoint = current_checkpoint(db)
    if checkpoint is None:
        return None
    leaves = _leaf_hashes(db)
    size = len(leaves)
    if 0 < since_size < size:
        consistency = notarylib.consistency_proof(leaves, since_size)
    else:
        # since_size == 0: first contact, nothing to connect.
        # since_size == size: same checkpoint, root equality is checked instead.
        # since_size > size: the tree the device remembers is AHEAD of us — no
        # honest proof exists; serve an empty one and let the device fail closed.
        consistency = []
    return {
        "entry": json.loads(leaf.entry_json),
        "leaf_index": leaf.leaf_index,
        "inclusion": notarylib.inclusion_path(leaves, leaf.leaf_index),
        "checkpoint": checkpoint_dict(checkpoint),
        "consistency": consistency,
    }


def offer_proofs(db: Session, release_row, since_size: int) -> dict | None:
    """The notary section of an offer: membership proof for the release's own
    leaf plus the consistency path from the device's stored checkpoint."""
    leaf = db.scalar(
        select(NotaryLeaf).where(
            NotaryLeaf.entry_type == "release", NotaryLeaf.ref_id == release_row.id
        )
    )
    if leaf is None:
        return None  # unreachable: leaf and release commit together
    return _proof_bundle(db, leaf, since_size)


def publication_proofs(db: Session, entry_type: str, ref_id: str) -> dict | None:
    """The notary section returned to the operator on (re)publication."""
    leaf = db.scalar(
        select(NotaryLeaf).where(
            NotaryLeaf.entry_type == entry_type, NotaryLeaf.ref_id == str(ref_id)
        )
    )
    if leaf is None:
        return None
    return _proof_bundle(db, leaf, 0)


# --------------------------------------------------------------------------- #
# Quarantine (permanent, per model) + evidence (content-deduped)
# --------------------------------------------------------------------------- #
def is_quarantined(db: Session, model: str) -> bool:
    return db.get(QuarantinedModel, model) is not None


def evidence_hash(model: str, kind: str, evidence: dict) -> str:
    return hashlib.sha256(
        trustlib.canonical_json({"kind": kind, "model": model, "evidence": evidence})
    ).hexdigest()


def record_evidence(
    db: Session, *, device_id: str, model: str, kind: str, evidence: dict, idempotency_key: str
) -> dict:
    """Store suspicious material and quarantine the affected model.

    The same material (same kind+model+evidence bytes) is stored exactly once
    no matter how often it is reported; repeats return duplicate=True. The
    quarantine row is insert-only and survives restarts (it is plain DB state).
    """
    if kind not in notarylib.EVIDENCE_KINDS:
        raise ValueError(f"unknown_evidence_kind:{kind}")
    ehash = evidence_hash(model, kind, evidence)
    with _lock:
        dup = db.scalar(select(NotaryEvidence).where(NotaryEvidence.evidence_hash == ehash))
        if dup is not None:
            return {"duplicate": True, "quarantined": True, "evidence_hash": ehash}
        db.add(
            NotaryEvidence(
                evidence_hash=ehash,
                device_id=device_id,
                model=model,
                kind=kind,
                detail_json=trustlib.canonical_str(evidence),
                idempotency_key=idempotency_key,
            )
        )
        if db.get(QuarantinedModel, model) is None:
            db.add(QuarantinedModel(model=model, reason=kind, evidence_hash=ehash))
        try:
            db.commit()
        except IntegrityError:
            # The UNIQUE(evidence_hash) backstop fired (concurrent first report
            # of the same material under multiple workers): still one copy.
            db.rollback()
            return {"duplicate": True, "quarantined": True, "evidence_hash": ehash}
        return {"duplicate": False, "quarantined": True, "evidence_hash": ehash}
