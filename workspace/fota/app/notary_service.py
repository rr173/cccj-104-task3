"""Control-plane notarization service: appends to the Merkle ledger, signs
checkpoints, builds witnesses, and enforces the permanent observation zone.

Atomicity (the core crash-safety contract)
------------------------------------------
A registration is ONE database transaction covering: the business row (root
link or signed release), the appended ledger leaf, and the signed checkpoint.
`append_entry()` never commits on its own — the publish call site commits all
three together, so a kill between "artifact row written" and "leaf settled"
rolls the artifact row back too: there is never a state where an artifact is
claimable but the ledger has no entry.

The leaf's request token is UNIQUE and the leaf hash is UNIQUE: six concurrent
calls sharing one token can settle at most one leaf, and a replay after a crash
returns the already-settled leaf — never a duplicate, never an orphan.

Equivocation
------------
Only the key-holder can sign checkpoints, so a second *validly signed*
checkpoint at an already-occupied tree size with a different root is
unambiguous log equivocation. It is retained (alternate=True), never replaces
the canonical checkpoint, and permanently quarantines every model present in
the compromised log — across process restarts.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, notary as nlib, trust as trustlib
from .models import (
    NotaryCheckpoint,
    NotaryLeaf,
    NotarySuspicion,
    QuarantinedModel,
)

# Log appends are serialized in-process; UNIQUE(seq)/UNIQUE(request_token)
# are the durable backstop under multiple workers.
_log_lock = threading.RLock()


class NotaryConflict(Exception):
    """Same request token used for different content (-> 409)."""


class EquivocationDetected(Exception):
    """A second validly-signed checkpoint at an occupied size/root conflict."""

    def __init__(self, tree_size: int, canonical_root: str, alternate_root: str, models: list[str]):
        super().__init__(f"equivocation@{tree_size}")
        self.tree_size = tree_size
        self.canonical_root = canonical_root
        self.alternate_root = alternate_root
        self.models = models


class CrashInjected(RuntimeError):
    """Test seam: the process "died" after ledger flush, before commit."""


# --------------------------------------------------------------------------- #
# Notary key (pinned by nodes; private half never leaves the control plane)
# --------------------------------------------------------------------------- #
def _load_or_create_keys() -> dict[str, str]:
    path = Path(config.NOTARY_KEYS_PATH)
    if path.exists():
        return json.loads(path.read_text())
    priv, pub = trustlib.generate_keypair()
    keys = {"private": priv, "public": pub, "key_id": trustlib.key_id(pub)}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(keys, indent=2))
    tmp.replace(path)
    return keys


def notary_keys() -> dict[str, str]:
    return _load_or_create_keys()


def notary_public() -> dict[str, str]:
    k = notary_keys()
    return {"key_id": k["key_id"], "public": k["public"]}


# --------------------------------------------------------------------------- #
# Read side
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return trustlib.iso_format(datetime.now(timezone.utc))


def current_checkpoint(db: Session) -> NotaryCheckpoint | None:
    return db.scalar(
        select(NotaryCheckpoint)
        .where(NotaryCheckpoint.canonical.is_(True))
        .order_by(NotaryCheckpoint.tree_size.desc())
        .limit(1)
    )


def tree_size(db: Session) -> int:
    cp = current_checkpoint(db)
    return int(cp.tree_size) if cp is not None else 0


def _ordered_leaves(db: Session) -> list[NotaryLeaf]:
    return db.scalars(select(NotaryLeaf).order_by(NotaryLeaf.seq.asc())).all()


def _leaf_hashes(leaves: list[NotaryLeaf]) -> list[bytes]:
    return [bytes.fromhex(l.leaf_hash) for l in leaves]


def _tree(db: Session) -> nlib.MerkleTree:
    return nlib.MerkleTree(_leaf_hashes(_ordered_leaves(db)))


def leaf_by_token(db: Session, token: str) -> NotaryLeaf | None:
    return db.scalar(select(NotaryLeaf).where(NotaryLeaf.request_token == token))


def leaf_for_kind_ref(db: Session, kind: str, ref: str) -> NotaryLeaf | None:
    return db.scalar(
        select(NotaryLeaf).where(NotaryLeaf.kind == kind, NotaryLeaf.ref == str(ref))
    )


def models_in_log(db: Session) -> list[str]:
    """Distinct models covered by release entries — the blast radius of an
    equivocation (a poisoned log invalidates every model whose artifacts are
    recorded in it)."""
    rows = db.scalars(
        select(NotaryLeaf.model)
        .where(NotaryLeaf.kind == nlib.ENTRY_KIND_RELEASE)
        .distinct()
    ).all()
    return sorted({m for m in rows if m})


# --------------------------------------------------------------------------- #
# Append (participates in the caller's transaction — never commits itself)
# --------------------------------------------------------------------------- #
def append_entry(
    db: Session,
    *,
    kind: str,
    ref: str,
    model: str | None,
    payload_sha256: str,
    request_token: str,
    committed_at: str | None = None,
) -> NotaryLeaf:
    """Append one canonical entry and sign the new checkpoint WITHIN the
    caller's open transaction. Returns the leaf row (already flushed).

    Idempotency: an existing leaf with the same request token is returned when
    its content is identical; a different content under the same token is a
    conflict. The UNIQUE(request_token)/UNIQUE(leaf_hash) constraints are the
    cross-worker backstop.
    """
    with _log_lock:
        registered_at = committed_at or _now_iso()
        entry = nlib.make_entry(
            kind=kind,
            ref=str(ref),
            model=model,
            payload_sha256=payload_sha256,
            registered_at=registered_at,
        )
        lh = nlib.entry_leaf_hash(entry).hex()

        existing = leaf_by_token(db, request_token)
        if existing is not None:
            if existing.leaf_hash != lh:
                raise NotaryConflict("request_token_conflict")
            return existing

        leaves = _ordered_leaves(db)
        # Defensive: a content-identical leaf can never occupy two positions.
        if any(l.leaf_hash == lh for l in leaves):
            dup = next(l for l in leaves if l.leaf_hash == lh)
            return dup

        leaf = NotaryLeaf(
            seq=len(leaves) + 1,
            kind=kind,
            ref=str(ref),
            model=model,
            payload_sha256=payload_sha256,
            entry_json=trustlib.canonical_str(entry),
            leaf_hash=lh,
            request_token=request_token,
        )
        db.add(leaf)
        db.flush()  # make the row visible to the tree build; NOT a durability point

        # Crash seam: simulate SIGKILL with the artifact+leaf rows flushed but
        # the transaction uncommitted. The connection is torn down; on reopen
        # neither row exists (atomic rollback), so no orphan / no double leaf.
        if config.CRASH_AFTER_LEAF_FLUSH and config.CRASH_AFTER_LEAF_FLUSH == request_token:
            db.connection().connection.close()  # kill the DBAPI connection
            raise CrashInjected("process killed after ledger flush, before commit")

        tree = _tree(db)
        root = tree.root.hex()
        size = tree.size
        keys = notary_keys()
        cp = nlib.sign_checkpoint(tree_size=size, root=root, time=_now_iso(), priv_hex=keys["private"])
        row = NotaryCheckpoint(
            tree_size=size,
            root=root,
            checkpoint_json=trustlib.canonical_str(
                nlib.checkpoint_payload(tree_size=size, root=root, time=cp["time"])
            ),
            signatures_json=trustlib.canonical_str(
                trustlib.normalize_signatures(cp["signatures"])
            ),
            canonical=True,
        )
        db.add(row)
        db.flush()
        return leaf


# --------------------------------------------------------------------------- #
# Witness bundles
# --------------------------------------------------------------------------- #
def _checkpoint_wire(cp: NotaryCheckpoint) -> dict:
    body = json.loads(cp.checkpoint_json)
    body["signatures"] = json.loads(cp.signatures_json)
    return body


def bundle_for(db: Session, leaf: NotaryLeaf, old_size: int) -> dict:
    """Membership witness for `leaf` plus the continuous (consistency) witness
    from the size the fetching node last remembered to the current size.

    A node at old_size 0 (or already current) needs no continuity hashes:
    bootstrap trusts the signed checkpoint, equal sizes anchor the same root.
    """
    leaves = _ordered_leaves(db)
    tree = nlib.MerkleTree(_leaf_hashes(leaves))
    idx = leaf.seq - 1
    # The membership witness is verified against the CURRENT checkpoint root:
    # inclusion proofs in an append-only tree remain valid at every later size.
    current = current_checkpoint(db)
    new_size = int(current.tree_size)
    proof = tree.consistency(max(0, old_size), new_size)
    b = nlib.WitnessBundle(
        key_id=notary_keys()["key_id"],
        public=notary_keys()["public"],
        checkpoint=_checkpoint_wire(current),
        leaf_index=idx,
        entry=json.loads(leaf.entry_json),
        inclusion=[h.hex() for h in tree.inclusion(idx)],
        old_size=max(0, old_size),
        consistency=[h.hex() for h in proof],
    )
    return nlib.bundle_to_wire(b)


def bundle_for_kind_ref(db: Session, kind: str, ref: str, old_size: int) -> dict | None:
    leaf = leaf_for_kind_ref(db, kind, ref)
    if leaf is None:
        return None
    return bundle_for(db, leaf, old_size)


# --------------------------------------------------------------------------- #
# Quarantine (permanent, durable, restart-surviving observation zone)
# --------------------------------------------------------------------------- #
def is_quarantined(db: Session, model: str | None) -> bool:
    if not model:
        return False
    return db.get(QuarantinedModel, model) is not None


def quarantine_models(
    db: Session, models, *, reason: str, detail: str, commit: bool = False
) -> list[str]:
    """Place each model in the permanent observation zone. Idempotent: an
    already-quarantined model is not re-created."""
    affected: list[str] = []
    for model in sorted({m for m in models if m}):
        if db.get(QuarantinedModel, model) is None:
            db.add(QuarantinedModel(model=model, reason=reason, detail=detail[:4000]))
            affected.append(model)
    if commit:
        db.commit()
    return affected


def list_quarantined(db: Session) -> list[dict]:
    rows = db.scalars(select(QuarantinedModel).order_by(QuarantinedModel.model)).all()
    return [
        {"model": q.model, "reason": q.reason, "detail": q.detail, "created_at": q.created_at}
        for q in rows
    ]


# --------------------------------------------------------------------------- #
# Equivocation intake (validly-signed alternate checkpoint at an occupied size)
# --------------------------------------------------------------------------- #
def admit_alternate_checkpoint(db: Session, checkpoint: dict) -> EquivocationDetected:
    """Verify a purported alternate checkpoint and, if it is validly signed by
    the notary key but conflicts with the canonical checkpoint at its tree
    size, retain it as evidence and permanently quarantine the affected
    models. Returns the equivocation event (always raised after persistence).
    """
    keys = notary_keys()
    nlib.verify_checkpoint_signature(checkpoint, keys["public"])
    size = int(checkpoint["tree_size"])
    alt_root = str(checkpoint["root"])

    canonical = db.scalar(
        select(NotaryCheckpoint)
        .where(NotaryCheckpoint.tree_size == size, NotaryCheckpoint.canonical.is_(True))
    )
    if canonical is None:
        raise NotaryConflict("no_canonical_checkpoint_at_size")
    if canonical.root == alt_root:
        raise NotaryConflict("checkpoint_identical_not_equivocation")

    with _log_lock:
        # Retain the alternate as durable evidence (deduplicated by size+root).
        existing_alt = db.scalar(
            select(NotaryCheckpoint).where(
                NotaryCheckpoint.tree_size == size,
                NotaryCheckpoint.root == alt_root,
                NotaryCheckpoint.canonical.is_(False),
            )
        )
        if existing_alt is None:
            db.add(
                NotaryCheckpoint(
                    tree_size=size,
                    root=alt_root,
                    checkpoint_json=trustlib.canonical_str(
                        nlib.checkpoint_payload(
                            tree_size=size, root=alt_root, time=str(checkpoint["time"])
                        )
                    ),
                    signatures_json=trustlib.canonical_str(
                        trustlib.normalize_signatures(checkpoint.get("signatures") or [])
                    ),
                    canonical=False,
                )
            )
        affected = models_in_log(db)
        detail = (
            f"two validly-signed checkpoints at tree_size={size}: "
            f"root {canonical.root} vs {alt_root}"
        )
        quarantine_models(db, affected, reason=nlib.EQUIVOCATION, detail=detail)
        db.commit()
        return EquivocationDetected(size, canonical.root, alt_root, affected)


# --------------------------------------------------------------------------- #
# Suspicion intake (node-side witness verification failures)
# --------------------------------------------------------------------------- #
def suspicion_evidence(
    *, kind: str, model: str | None, detail: str, material: dict
) -> tuple[str, str]:
    """Deterministic content hash of the reported material so the same
    evidence, reported repeatedly by anyone, collapses to one stored row."""
    evidence = {
        "kind": kind,
        "model": model,
        "detail": detail,
        "material": material or {},
    }
    blob = trustlib.canonical_json(evidence)
    import hashlib

    return hashlib.sha256(blob).hexdigest(), trustlib.canonical_str(evidence)


def report_suspicion(
    db: Session,
    *,
    device_id: str,
    kind: str,
    model: str | None,
    detail: str,
    material: dict,
) -> dict:
    """Store one row per distinct piece of evidence. A repeat returns
    duplicate=True with zero new side effects. Any notarization suspicion
    against a named model permanently quarantines that model."""
    ev_hash, ev_json = suspicion_evidence(kind=kind, model=model, detail=detail, material=material)
    dup = db.scalar(select(NotarySuspicion).where(NotarySuspicion.evidence_hash == ev_hash))
    if dup is not None:
        return {"id": dup.id, "duplicate": True, "quarantined": []}

    row = NotarySuspicion(
        device_id=device_id,
        model=model,
        kind=kind,
        evidence_hash=ev_hash,
        evidence_json=ev_json,
        detail=detail[:4000],
        duplicate=False,
    )
    db.add(row)
    quarantined: list[str] = []
    if model:
        quarantined = quarantine_models(db, [model], reason=kind, detail=detail)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "duplicate": False, "quarantined": quarantined}


def list_suspicions(db: Session, *, model: str | None = None, kind: str | None = None):
    q = select(NotarySuspicion).order_by(NotarySuspicion.id.desc())
    if model:
        q = q.where(NotarySuspicion.model == model)
    if kind:
        q = q.where(NotarySuspicion.kind == kind)
    return [
        {
            "id": s.id,
            "device_id": s.device_id,
            "model": s.model,
            "kind": s.kind,
            "evidence_hash": s.evidence_hash,
            "evidence": json.loads(s.evidence_json),
            "detail": s.detail,
            "duplicate": s.duplicate,
            "created_at": s.created_at,
        }
        for s in db.scalars(q).all()
    ]
