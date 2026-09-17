"""Offline release signing: canonical metadata, ed25519 envelopes, validation.

This module is deliberately free of any app/server imports: the SAME code runs
on the service (publish-time verification) and on the device (pre-flash
validation), so canonicalization and verification logic can never drift apart.

Trust model (TUF-style, thresholds fixed at 1 signature):

* Every signed document is canonical JSON (sorted keys, tight separators,
  UTF-8) — deterministic across implementations and processes.
* Root metadata is versioned (1, 2, 3, ...). v1 is self-signed by its own
  root-role keys (devices bootstrap trust-on-first-use; production would pin
  root v1 at manufacturing).
* Root vN+1 must carry valid signatures from root-role keys of vN (the old
  root authorizes the transition) AND from root-role keys of vN+1 (the new
  root commits). A missing link or a missing authorization fails closed.
* Release metadata binds {model, display version, artifact digest, monotonic
  security counter, expiry} and must be signed by a non-revoked release-role
  key of the device's CURRENT root (after chain catch-up).
* Devices persist the highest security counter they have accepted and refuse
  anything below it (downgrade resistance).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Validation failure reasons — also used as `release_rejected` receipt reasons.
MISSING_LINK = "missing_link"
EXPIRED = "expired"
BAD_SIGNATURE = "bad_signature"
REVOKED_SIGNER = "revoked_signer"
COUNTER_ROLLBACK = "counter_rollback"
DIGEST_MISMATCH = "digest_mismatch"
MODEL_MISMATCH = "model_mismatch"
MISSING_METADATA = "missing_metadata"
NO_TRUST_ROOT = "no_trust_root"
MALFORMED = "malformed"


class TrustError(Exception):
    """A validation step failed closed. `reason` is one of the codes above."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}:{detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------- #
# Canonical (deterministic) serialization — the signed bytes
# --------------------------------------------------------------------------- #
def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_str(obj: Any) -> str:
    return canonical_json(obj).decode("utf-8")


# --------------------------------------------------------------------------- #
# Time helpers — metadata expiry uses a fixed ISO-8601 UTC format
# --------------------------------------------------------------------------- #
def iso_format(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_after(seconds: float) -> str:
    return iso_format(datetime.now(timezone.utc) + timedelta(seconds=seconds))


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_expired(expires: str, now: datetime) -> bool:
    return parse_iso(expires) <= now


# --------------------------------------------------------------------------- #
# ed25519 primitives (keys are raw 32-byte hex; signatures are 64-byte hex)
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[str, str]:
    """Return (private_hex, public_hex). Private keys stay OFFLINE — the
    service and devices only ever see public keys inside signed metadata."""
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv_hex, pub_hex


def _public_of(priv_hex: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def key_id(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:16]


def sign(message: bytes, priv_hex: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv.sign(message).hex()


def verify(message: bytes, sig_hex: str, pub_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), message
        )
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Metadata builders (used by the offline signer: tests, seed, demo tooling)
# --------------------------------------------------------------------------- #
def key_entry(pub_hex: str, roles: list[str], revoked: bool = False) -> dict:
    return {
        "type": "ed25519",
        "public": pub_hex,
        "roles": sorted(roles),
        "revoked": bool(revoked),
    }


def root_metadata(version: int, keys: dict[str, dict], expires: str) -> dict:
    return {"type": "root", "version": int(version), "expires": expires, "keys": keys}


def release_metadata(
    *,
    model: str,
    version: str,
    artifact_sha256: str,
    security_counter: int,
    expires: str,
    release_id: str | None = None,
) -> dict:
    rid = release_id or hashlib.sha256(
        f"{model}:{version}:{artifact_sha256}".encode()
    ).hexdigest()[:16]
    return {
        "type": "release",
        "release_id": rid,
        "model": model,
        "version": version,
        "artifact_sha256": artifact_sha256,
        "security_counter": int(security_counter),
        "expires": expires,
    }


def sign_envelope(metadata: dict, priv_hex: str) -> dict:
    """One signature entry over the canonical serialization of `metadata`."""
    pub = _public_of(priv_hex)
    return {"key_id": key_id(pub), "sig": sign(canonical_json(metadata), priv_hex)}


def normalize_signatures(signatures: list[dict]) -> list[dict]:
    """Deterministic signature list (sorted by key id) so identical envelopes
    hash identically regardless of signature ordering."""
    out = [{"key_id": str(s["key_id"]), "sig": str(s["sig"])} for s in signatures]
    out.sort(key=lambda s: s["key_id"])
    return out


def envelope_hash(metadata: dict, signatures: list[dict]) -> str:
    return hashlib.sha256(
        canonical_json(
            {"metadata": metadata, "signatures": normalize_signatures(signatures)}
        )
    ).hexdigest()


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _authorized_keys(authorizing_root_meta: dict, role: str) -> dict[str, dict]:
    keys = authorizing_root_meta.get("keys") or {}
    return {
        kid: k
        for kid, k in keys.items()
        if role in (k.get("roles") or []) and not k.get("revoked", False)
    }


def verify_threshold(
    metadata: dict, signatures: list[dict], authorizing_root_meta: dict, role: str
) -> None:
    """Require >=1 valid signature from an authorized, non-revoked `role` key
    listed in `authorizing_root_meta`. Raises TrustError otherwise."""
    msg = canonical_json(metadata)
    authorized = _authorized_keys(authorizing_root_meta, role)
    saw_revoked = False
    for sig in normalize_signatures(signatures):
        kid = sig["key_id"]
        if kid in authorized:
            if verify(msg, sig["sig"], authorized[kid]["public"]):
                return
        else:
            entry = (authorizing_root_meta.get("keys") or {}).get(kid)
            if entry and entry.get("revoked"):
                saw_revoked = True
    if saw_revoked:
        raise TrustError(
            REVOKED_SIGNER,
            f"signer revoked in root v{authorizing_root_meta.get('version')}",
        )
    raise TrustError(BAD_SIGNATURE, f"no valid {role}-role signature")


@dataclass
class TrustStore:
    """The device's persisted trust state: current root + highest accepted
    security counter. Must be written atomically (tmp file + rename)."""

    root_version: int
    root_metadata: dict
    highest_counter: int = 0

    def to_dict(self) -> dict:
        return {
            "root_version": self.root_version,
            "root_metadata": self.root_metadata,
            "highest_counter": self.highest_counter,
        }

    @staticmethod
    def from_dict(d: dict) -> "TrustStore":
        return TrustStore(
            root_version=int(d["root_version"]),
            root_metadata=d["root_metadata"],
            highest_counter=int(d.get("highest_counter", 0)),
        )


def validate_root_link(
    current: TrustStore | None, envelope: dict, now: datetime
) -> TrustStore:
    """Validate one root rotation link against the current trust state.

    Fails closed on: version gaps (missing link), expired metadata, missing
    authorization from the old root, or missing self-commitment of the new
    root. Returns the next trust state (counter carried over); the caller
    persists it atomically only after the WHOLE chain validates.
    """
    meta = (envelope or {}).get("metadata")
    sigs = (envelope or {}).get("signatures") or []
    if not isinstance(meta, dict) or meta.get("type") != "root":
        raise TrustError(MALFORMED, "not root metadata")
    try:
        version = int(meta.get("version"))
    except (TypeError, ValueError):
        raise TrustError(MALFORMED, "bad root version")
    expected = (current.root_version if current else 0) + 1
    if version != expected:
        raise TrustError(MISSING_LINK, f"need root v{expected}, got v{version}")
    expires = meta.get("expires")
    if not expires or is_expired(str(expires), now):
        raise TrustError(EXPIRED, f"root v{version} expired")
    # The new root commits to itself ...
    verify_threshold(meta, sigs, meta, "root")
    # ... and the old root authorizes the transition (bootstrap v1 is
    # self-authorized: trust-on-first-use, pinned at factory in production).
    if current is not None:
        verify_threshold(meta, sigs, current.root_metadata, "root")
    return TrustStore(version, meta, current.highest_counter if current else 0)


def apply_root_chain(
    current: TrustStore | None, chain: list[dict], now: datetime
) -> TrustStore:
    """Fold a chain of consecutive root links. All-or-nothing: if any link
    fails, the returned-from exception means the caller keeps `current`."""
    trust = current
    for envelope in chain:
        trust = validate_root_link(trust, envelope, now)
    return trust if trust is not None else current


def validate_release(
    envelope: dict,
    trust: TrustStore | None,
    *,
    device_model: str,
    artifact_sha256: str,
    now: datetime,
) -> dict:
    """Validate a signed release against the device's trust state. Returns the
    release metadata on success; raises TrustError (fail closed) otherwise."""
    meta = (envelope or {}).get("metadata")
    sigs = (envelope or {}).get("signatures") or []
    if trust is None:
        raise TrustError(NO_TRUST_ROOT, "no trusted root installed")
    if not isinstance(meta, dict) or meta.get("type") != "release":
        raise TrustError(MALFORMED, "not release metadata")
    if meta.get("model") != device_model:
        raise TrustError(
            MODEL_MISMATCH, f"release for {meta.get('model')}, device is {device_model}"
        )
    expires = meta.get("expires")
    if not expires or is_expired(str(expires), now):
        raise TrustError(EXPIRED, "release metadata expired")
    try:
        counter = int(meta.get("security_counter"))
    except (TypeError, ValueError):
        raise TrustError(MALFORMED, "bad security counter")
    if counter < trust.highest_counter:
        raise TrustError(
            COUNTER_ROLLBACK,
            f"counter {counter} below accepted {trust.highest_counter}",
        )
    if meta.get("artifact_sha256") != artifact_sha256:
        raise TrustError(DIGEST_MISMATCH, "artifact digest does not match offer")
    verify_threshold(meta, sigs, trust.root_metadata, "release")
    return meta
