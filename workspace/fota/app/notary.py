"""Software-supply notarization: append-only Merkle log math + canonical wire
objects, shared verbatim by the control plane (signing/serving) and by nodes
(verification). Like app/trust.py this module deliberately imports neither the
web layer nor the ORM, so the verifier a node runs can never drift from the
witness the control plane produces.

Tree shape (binary Merkle, RFC 9162-compatible leaf/node domain separation):

* leaf hash  = SHA256(0x00 || canonical_entry_bytes)
* node hash  = SHA256(0x01 || left_hash || right_hash)
* MTH over n leaves splits at the largest power of two < n, so identical leaf
  prefixes always produce identical intermediate hashes — an append-only tree.

Membership witnesses follow RFC 9162 §2.1.3 (inclusion proof).

The continuity witness ("consistency proof") is a small, self-contained
append-only proof in at most 2*ceil(log2(n)) hashes:

* `old_frontier`: the balanced power-of-two subtree roots partitioning leaves
  [0, m) (popcount(m) hashes). A verifier that already trusts old_root folds
  them left-to-right and demands the result equal old_root.
* `extension`: aligned balanced subtree roots covering [m, n), generated
  greedily (at each position take the largest aligned block that fits). Pushing
  them through the same frontier merge reproduces new_root.

All block heights are derived deterministically from (m, n), so the verifier
re-runs the exact same geometry the generator used — a verifier cannot be fed a
plausible-looking hash for the wrong slot.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from . import trust as trustlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# Witness failure reasons — also used as suspicion `kind` codes.
BAD_WITNESS = "witness_tampered"
BROKEN_CHAIN = "broken_chain"
TREE_SHRINK = "tree_shrink"
EQUIVOCATION = "equivocation"
BAD_CHECKPOINT_SIGNATURE = "bad_checkpoint_signature"
ENTRY_BINDING_MISMATCH = "entry_binding_mismatch"


class NotaryError(Exception):
    """A notarization check failed closed. `reason` is one of the codes above."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}:{detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------- #
# Hashing primitives
# --------------------------------------------------------------------------- #
def leaf_hash(entry_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + entry_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    return hashlib.sha256(b"").digest()


def root_from_leaves(leaf_hashes: list[bytes]) -> bytes:
    if not leaf_hashes:
        return empty_root()
    memo: dict[tuple[int, int], bytes] = {}

    def build(lo: int, n: int) -> bytes:
        if n == 1:
            return leaf_hashes[lo]
        cached = memo.get((lo, n))
        if cached is not None:
            return cached
        k = 1 << (n - 1).bit_length() - 1
        h = node_hash(build(lo, k), build(lo + k, n - k))
        memo[(lo, n)] = h
        return h

    return build(0, len(leaf_hashes))


class MerkleTree:
    """A log tree over a prefix of leaves, built once in O(n). Subtree roots
    are memoized by (offset, length) so membership + continuity witnesses are
    O(log n) of hashing after construction, not O(n log n)."""

    def __init__(self, leaf_hashes: list[bytes]):
        self.leaves = leaf_hashes
        self._sub: dict[tuple[int, int], bytes] = {}

    @property
    def size(self) -> int:
        return len(self.leaves)

    @property
    def root(self) -> bytes:
        return self.subtree(0, len(self.leaves)) if self.leaves else empty_root()

    def subtree(self, offset: int, length: int) -> bytes:
        """Root of the complete subtree covering exactly [offset, offset+len)."""
        if length == 1:
            return self.leaves[offset]
        cached = self._sub.get((offset, length))
        if cached is not None:
            return cached
        k = 1 << (length - 1).bit_length() - 1
        h = node_hash(self.subtree(offset, k), self.subtree(offset + k, length - k))
        self._sub[(offset, length)] = h
        return h

    def inclusion(self, index: int) -> list[bytes]:
        n = len(self.leaves)
        if not 0 <= index < n:
            raise NotaryError(BAD_WITNESS, f"leaf index {index} out of range {n}")
        top_down: list[bytes] = []
        lo, hi = 0, n
        while hi - lo > 1:
            k = lo + (1 << ((hi - lo - 1).bit_length() - 1))
            if index < k:
                top_down.append(self.subtree(k, hi - k))
                hi = k
            else:
                top_down.append(self.subtree(lo, k - lo))
                lo = k
        return top_down[::-1]

    def consistency(self, m: int, n: int) -> list[bytes]:
        if not 0 <= m <= n:
            raise NotaryError(BROKEN_CHAIN, f"bad consistency span {m}->{n}")
        if m == 0 or m == n:
            return []
        proof: list[bytes] = []
        pos = 0
        for size in _old_frontier_geometry(m):
            proof.append(self.subtree(pos, size))
            pos += size
        for size in _extension_geometry(m, n):
            proof.append(self.subtree(pos, size))
            pos += size
        return proof


# --------------------------------------------------------------------------- #
# Inclusion (membership) witnesses — RFC 9162 §2.1.3 shape
# --------------------------------------------------------------------------- #
def _path_geometry(size: int, index: int) -> list[bool]:
    """Left/right turns on the top-down root-to-leaf path. At each level the
    segment splits at k (largest power of two strictly smaller than the
    segment); True means the path went left. Deterministic from (size, index)
    alone — a verifier needs no side hints carried inside the proof."""
    if not 0 <= index < size:
        raise NotaryError(BAD_WITNESS, f"leaf index {index} out of range {size}")
    turns: list[bool] = []
    lo, hi = 0, size
    while hi - lo > 1:
        k = lo + (1 << ((hi - lo - 1).bit_length() - 1))
        if index < k:
            turns.append(True)
            hi = k
        else:
            turns.append(False)
            lo = k
    return turns


def inclusion_proof(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """Bottom-up sibling hashes proving leaf `index` is in the tree."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise NotaryError(BAD_WITNESS, f"leaf index {index} out of range {n}")
    top_down: list[bytes] = []
    lo, hi = 0, n
    while hi - lo > 1:
        k = lo + (1 << ((hi - lo - 1).bit_length() - 1))
        if index < k:
            top_down.append(root_from_leaves(leaf_hashes[k:hi]))
            hi = k
        else:
            top_down.append(root_from_leaves(leaf_hashes[lo:k]))
            lo = k
    return top_down[::-1]


def verify_inclusion(
    *, index: int, size: int, leaf: bytes, proof: list[bytes], root: bytes
) -> None:
    """Raise NotaryError unless `leaf` sits at `index` in a size-`size` tree
    with root `root`. Path turns are re-derived from (size, index), so a proof
    is nothing but sibling hashes — it cannot be reordered into a path that
    verifies against a different leaf."""
    if size <= 0 or not 0 <= index < size:
        raise NotaryError(BAD_WITNESS, f"bad index/size {index}/{size}")
    turns = _path_geometry(size, index)
    if len(proof) != len(turns):
        raise NotaryError(BAD_WITNESS, "inclusion proof has the wrong number of hashes")
    r = leaf
    # Fold bottom-up: reverse the top-down turns; True (went left) means the
    # sibling hash belongs on the right.
    for p, went_left in zip(proof, reversed(turns)):
        r = node_hash(r, p) if went_left else node_hash(p, r)
    if r != root:
        raise NotaryError(BAD_WITNESS, "inclusion proof does not fold to checkpoint root")


# --------------------------------------------------------------------------- #
# Continuity (append-only / consistency) witnesses
# --------------------------------------------------------------------------- #
def _old_frontier_geometry(m: int) -> list[int]:
    """Block heights of the balanced partition of [0, m)."""
    heights: list[int] = []
    pos = 0
    remaining = m
    while remaining:
        h = remaining.bit_length() - 1
        size = 1 << h
        heights.append(size)
        pos += size
        remaining -= size
    return heights


def _extension_geometry(m: int, n: int) -> list[int]:
    """Sizes of the aligned balanced subtrees covering [m, n), in append
    order: at each position take the largest power-of-two block that both fits
    the remainder and starts at a matching alignment boundary."""
    blocks: list[int] = []
    pos = m
    while pos < n:
        align_h = (pos & -pos).bit_length() - 1 if pos else 64
        fit_h = (n - pos).bit_length() - 1
        h = min(align_h, fit_h)
        size = 1 << h
        blocks.append(size)
        pos += size
    return blocks


def consistency_proof(leaf_hashes: list[bytes], m: int, n: int) -> list[bytes]:
    """Append-only witness from tree size m to size n (0 <= m <= n).

    Empty for bootstrap (m == 0, nothing remembered yet) and for an unchanged
    tree (m == n); otherwise the old partition of [0, m), largest-first,
    followed by the aligned extension blocks covering [m, n)."""
    if not 0 <= m <= n:
        raise NotaryError(BROKEN_CHAIN, f"bad consistency span {m}->{n}")
    if m == 0 or m == n:
        return []
    proof: list[bytes] = []
    pos = 0
    for size in _old_frontier_geometry(m):
        proof.append(root_from_leaves(leaf_hashes[pos:pos + size]))
        pos += size
    for size in _extension_geometry(m, n):
        proof.append(root_from_leaves(leaf_hashes[pos:pos + size]))
        pos += size
    return proof


def _root_of_frontier(frontier: list[tuple[bytes, int]]) -> bytes:
    """Root of a carry frontier returned largest-height-first: fold from the
    smallest (last) with each larger block on the left."""
    if len(frontier) == 1:
        return frontier[0][0]
    acc = frontier[-1][0]
    for block, _ in reversed(frontier[:-1]):
        acc = node_hash(block, acc)
    return acc


def _merge_frontier_blocks(descending_blocks: list[bytes]) -> bytes:
    """Root of complete subtree roots given largest-first."""
    acc = descending_blocks[-1]
    for block in reversed(descending_blocks[:-1]):
        acc = node_hash(block, acc)
    return acc


def verify_consistency(
    *, m: int, n: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> None:
    """Raise NotaryError unless `proof` proves the tree at n extends the tree
    at m whose root was `old_root`."""
    if m < 0 or n < m:
        raise NotaryError(BROKEN_CHAIN, f"tree size moved backwards {m}->{n}")
    if m == 0:
        if proof:
            raise NotaryError(BROKEN_CHAIN, "bootstrap consistency proof must be empty")
        return
    if m == n:
        if proof or old_root != new_root:
            raise NotaryError(BROKEN_CHAIN, "equal-size consistency must anchor the same root")
        return
    n_old = _popcount(m)
    old_sizes = _old_frontier_geometry(m)  # largest-first partition of [0, m)
    ext_sizes = _extension_geometry(m, n)  # aligned append-order partition of [m, n)
    if len(proof) != n_old + len(ext_sizes):
        raise NotaryError(BROKEN_CHAIN, "continuity witness has the wrong number of hashes")
    old_blocks = proof[:n_old]
    if _merge_frontier_blocks(old_blocks) != old_root:
        raise NotaryError(BROKEN_CHAIN, "old frontier does not fold to the remembered root")

    # Seed the live append-frontier exactly as it stood after m appends
    # (largest-height first, the layout `_reduce_frontier` produces), then push
    # the extension blocks through the same binary carries. All geometry is
    # derived from (m, n), never from the supplied hashes.
    frontier: list[tuple[bytes, int]] = list(zip(old_blocks, old_sizes))
    for block, size in zip(proof[n_old:], ext_sizes):
        frontier.append((block, size))
        while len(frontier) >= 2 and frontier[-1][1] == frontier[-2][1]:
            right_h, right_s = frontier.pop()
            left_h, _ = frontier.pop()
            frontier.append((node_hash(left_h, right_h), right_s * 2))
    if sum(s for _, s in frontier) != n:
        raise NotaryError(BROKEN_CHAIN, "extension blocks do not cover the new tree")
    if _root_of_frontier(frontier) != new_root:
        raise NotaryError(BROKEN_CHAIN, "continuity witness does not fold to the new root")


def _popcount(x: int) -> int:
    return bin(x).count("1")


# --------------------------------------------------------------------------- #
# Canonical ledger entries
# --------------------------------------------------------------------------- #
ENTRY_KIND_RELEASE = "release"       # binary artifact (signed release)
ENTRY_KIND_ROOT = "root"             # trust handoff (root-rotation link)


def make_entry(
    *, kind: str, ref: str, model: str | None, payload_sha256: str, registered_at: str
) -> dict[str, Any]:
    return {
        "kind": kind,
        "ref": str(ref),
        "model": model,
        "payload_sha256": payload_sha256,
        "registered_at": registered_at,
    }


def entry_bytes(entry: dict[str, Any]) -> bytes:
    return trustlib.canonical_json(entry)


def entry_leaf_hash(entry: dict[str, Any]) -> bytes:
    return leaf_hash(entry_bytes(entry))


# --------------------------------------------------------------------------- #
# Signed checkpoints
# --------------------------------------------------------------------------- #
def checkpoint_payload(*, tree_size: int, root: str, time: str) -> dict[str, Any]:
    return {"tree_size": int(tree_size), "root": str(root), "time": str(time)}


def sign_checkpoint(*, tree_size: int, root: str, time: str, priv_hex: str) -> dict[str, Any]:
    payload = checkpoint_payload(tree_size=tree_size, root=root, time=time)
    return {
        "tree_size": int(tree_size),
        "root": str(root),
        "time": str(time),
        "signatures": [trustlib.sign_envelope(payload, priv_hex)],
    }


def checkpoint_bytes(cp: dict[str, Any]) -> bytes:
    return trustlib.canonical_json(
        checkpoint_payload(tree_size=cp["tree_size"], root=cp["root"], time=cp["time"])
    )


def verify_checkpoint_signature(cp: dict[str, Any], public_hex: str) -> None:
    """Validate that the checkpoint carries one good ed25519 signature by the
    pinned notary key over its canonical serialization."""
    try:
        size, root, time_ = int(cp["tree_size"]), str(cp["root"]), str(cp["time"])
    except (KeyError, TypeError, ValueError):
        raise NotaryError(BAD_CHECKPOINT_SIGNATURE, "malformed checkpoint")
    if size <= 0 or len(root) != 64:
        raise NotaryError(BAD_CHECKPOINT_SIGNATURE, "malformed checkpoint root/size")
    msg = checkpoint_bytes({"tree_size": size, "root": root, "time": time_})
    for sig in cp.get("signatures") or []:
        if trustlib.verify(msg, str(sig.get("sig", "")), public_hex):
            return
    raise NotaryError(BAD_CHECKPOINT_SIGNATURE, "checkpoint not signed by the notary key")


# --------------------------------------------------------------------------- #
# Bundle handed to fetching nodes
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class WitnessBundle:
    key_id: str
    public: str
    checkpoint: dict[str, Any]
    leaf_index: int          # 0-based
    entry: dict[str, Any]
    inclusion: list[str]     # hex sibling hashes
    old_size: int
    consistency: list[str]   # hex hashes (empty at bootstrap / equal size)


def bundle_to_wire(b: WitnessBundle) -> dict[str, Any]:
    return {
        "key_id": b.key_id,
        "public": b.public,
        "checkpoint": b.checkpoint,
        "leaf": {"index": b.leaf_index, "entry": b.entry},
        "inclusion": b.inclusion,
        "consistency": {"old_size": b.old_size, "new_size": int(b.checkpoint["tree_size"]),
                        "proof": b.consistency},
    }
