"""Supply-chain notarization: append-only Merkle tree + signed checkpoints.

This module is deliberately free of any app/server imports: the SAME code runs
on the service (proof generation, checkpoint signing) and on the device
(proof verification), so the canonical encoding and the Merkle math can never
drift apart — exactly like `app/trust.py` does for release signing.

Model (RFC 6962 style):
* Every notarized statement (a trust-root handoff or a signed release) is a
  canonically-encoded entry (deterministic JSON: sorted keys, tight separators).
* Entries are ONLY ever appended to the tail of one Merkle tree:
  leaf  = SHA256(0x00 || entry_bytes), node = SHA256(0x01 || left || right).
* Every tree state is summarized by a checkpoint {tree_size, root_hash}
  signed by the notary key. Devices pin the notary public key (TOFU, like the
  trust root) and persist the newest checkpoint they verified.
* A fetch response carries two proofs, both logarithmic in the tree size:
  - inclusion: the entry's audit path to the checkpoint root;
  - consistency: the proof that the device's stored checkpoint is a prefix of
    the served checkpoint. A long-dormant device therefore downloads O(log n)
    hashes, never the full history.

Verification failures are evidence of notary misbehavior; the `KIND_*`
constants are the evidence kinds a device reports to the control plane.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .trust import canonical_json

# --------------------------------------------------------------------------- #
# Evidence kinds (notary misbehavior detected by a verifying device)
# --------------------------------------------------------------------------- #
KIND_SPLIT_VIEW = "checkpoint_root_mismatch"      # same tree size, different root
KIND_TREE_SHRANK = "tree_shrank"                  # served tree smaller than stored
KIND_CONSISTENCY = "consistency_proof_invalid"    # old entries cannot be connected
KIND_INCLUSION = "inclusion_proof_invalid"        # membership proof bytes tampered
KIND_CHECKPOINT_SIG = "checkpoint_signature_invalid"  # bad signature / wrong notary key

EVIDENCE_KINDS = frozenset(
    {KIND_SPLIT_VIEW, KIND_TREE_SHRANK, KIND_CONSISTENCY, KIND_INCLUSION, KIND_CHECKPOINT_SIG}
)


class NotaryError(Exception):
    """A notary proof failed verification (fail closed). `kind` is one of the
    KIND_* evidence kinds above."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}:{detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


# --------------------------------------------------------------------------- #
# Merkle tree primitives (RFC 6962 §2.1)
# --------------------------------------------------------------------------- #
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_bytes(entry: dict) -> bytes:
    """The canonical encoding of a tree entry — the only bytes ever appended."""
    return canonical_json(entry)


def leaf_hash(entry: dict) -> str:
    return _sha256(_LEAF_PREFIX + entry_bytes(entry))


def node_hash(left_hex: str, right_hex: str) -> str:
    return _sha256(_NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1 << (n.bit_length() - 1)
    return k if k < n else k >> 1


def mth(leaf_hashes: list[str]) -> str:
    """Merkle Tree Hash over already-hashed leaves. Empty tree hashes the
    empty string by convention (no checkpoint is ever issued for it)."""
    if not leaf_hashes:
        return _sha256(b"")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    k = _split(len(leaf_hashes))
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


# --------------------------------------------------------------------------- #
# Inclusion proofs (audit paths) — RFC 6962 §2.1.1
# --------------------------------------------------------------------------- #
def inclusion_path(leaf_hashes: list[str], index: int) -> list[str]:
    """Sibling hashes proving leaf `index` sits in the tree, bottom-up."""
    if not 0 <= index < len(leaf_hashes):
        raise ValueError("leaf index out of range")
    proof: list[str] = []
    _incl(leaf_hashes, 0, len(leaf_hashes), index, proof)
    return proof


def _incl(leaves: list[str], off: int, n: int, m: int, proof: list[str]) -> None:
    if n == 1:
        return
    k = _split(n)
    if m - off < k:
        _incl(leaves, off, k, m, proof)
        proof.append(mth(leaves[off + k:off + n]))
    else:
        _incl(leaves, off + k, n - k, m, proof)
        proof.append(mth(leaves[off:off + k]))


def verify_inclusion(
    entry: dict, leaf_index: int, tree_size: int, path: list[str], root_hash: str
) -> bool:
    """Recompute the root from the entry and its audit path; accept iff it
    equals the checkpoint root and the path length is exactly consumed."""
    if not (0 <= leaf_index < tree_size) or tree_size < 1:
        return False
    it = iter(path or [])
    try:
        got = _verify_incl(leaf_index, tree_size, leaf_hash(entry), it)
    except (StopIteration, ValueError):
        return False
    if next(it, None) is not None:
        return False  # trailing junk in the proof
    return got == root_hash


def _verify_incl(m: int, n: int, h: str, it) -> str:
    if n == 1:
        return h
    k = _split(n)
    if m < k:
        left = _verify_incl(m, k, h, it)
        return node_hash(left, next(it))
    right = _verify_incl(m - k, n - k, h, it)
    return node_hash(next(it), right)


# --------------------------------------------------------------------------- #
# Consistency proofs — RFC 6962 §2.1.2
# --------------------------------------------------------------------------- #
def consistency_proof(leaf_hashes: list[str], old_size: int) -> list[str]:
    """Proof that the first `old_size` leaves are a prefix of the current
    tree. Empty when there is nothing to prove (old_size 0 or current)."""
    n = len(leaf_hashes)
    if old_size <= 0 or old_size >= n:
        return []
    proof: list[str] = []
    _subproof(leaf_hashes, 0, n, old_size, True, proof)
    return proof


def _subproof(leaves: list[str], off: int, n: int, m: int, b: bool, proof: list[str]) -> None:
    if m == n:
        if not b:
            proof.append(mth(leaves[off:off + n]))
        return
    k = _split(n)
    if m <= k:
        _subproof(leaves, off, k, m, b, proof)
        proof.append(mth(leaves[off + k:off + n]))
    else:
        _subproof(leaves, off + k, n - k, m - k, False, proof)
        proof.append(mth(leaves[off:off + k]))


# Sentinel for "subtree hash certified by the claimed old root" — arises only
# on the leftmost spine of the proof when the old tree is a perfect subtree
# (its root is the stored checkpoint root itself, taken as the seed).
_OLD: Any = object()


def _combine(a, b):
    if a is _OLD or b is _OLD or isinstance(a, tuple) or isinstance(b, tuple):
        return ("node", a, b)
    return node_hash(a, b)


def _resolve(expr, old_root: str) -> str:
    if expr is _OLD:
        return old_root
    if isinstance(expr, tuple):
        return node_hash(_resolve(expr[1], old_root), _resolve(expr[2], old_root))
    return expr


def verify_consistency(
    old_size: int, old_root: str, new_size: int, new_root: str, proof: list[str]
) -> bool:
    """Verify that the tree grew append-only from (old_size, old_root) to
    (new_size, new_root). Both roots are reconstructed from the proof; the
    old root the device stored is the trust anchor for the comparison."""
    if old_size == 0:
        return not proof
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size > new_size or not proof:
        return False
    it = iter(proof)
    try:
        old_expr, new_expr = _verify_sub(old_size, new_size, it, True)
    except (StopIteration, ValueError):
        return False
    if next(it, None) is not None:
        return False  # trailing junk in the proof
    return (
        _resolve(old_expr, old_root) == old_root
        and _resolve(new_expr, old_root) == new_root
    )


def _verify_sub(m: int, n: int, it, b: bool):
    """Mirror of _subproof: returns (old_expr, new_expr) for a subtree of size
    n whose first m leaves belong to the old tree, consuming proof nodes in
    exactly the order generation emitted them."""
    if m == n:
        if b:
            return _OLD, _OLD
        p = next(it)
        return p, p
    k = _split(n)
    if m <= k:
        old_l, new_l = _verify_sub(m, k, it, b)
        new_r = next(it)
        return old_l, _combine(new_l, new_r)
    old_r, new_r = _verify_sub(m - k, n - k, it, False)
    left = next(it)
    return _combine(left, old_r), _combine(left, new_r)


# --------------------------------------------------------------------------- #
# Signed checkpoints
# --------------------------------------------------------------------------- #
def checkpoint_payload(tree_size: int, root_hash: str) -> dict:
    return {"type": "checkpoint", "tree_size": int(tree_size), "root_hash": root_hash}


def sign_checkpoint(tree_size: int, root_hash: str, priv_hex: str) -> str:
    from .trust import sign

    return sign(canonical_json(checkpoint_payload(tree_size, root_hash)), priv_hex)


def verify_checkpoint_signature(checkpoint: dict, pub_hex: str) -> bool:
    """The checkpoint is only trustworthy if the notary key signed the exact
    {tree_size, root_hash} pair — extra/rewritten fields fail closed."""
    from .trust import verify

    try:
        size = int(checkpoint["tree_size"])
        root = str(checkpoint["root_hash"])
        sig = str(checkpoint["signature"])
    except (KeyError, TypeError, ValueError):
        return False
    return verify(canonical_json(checkpoint_payload(size, root)), sig, pub_hex)
