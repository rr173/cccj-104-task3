"""Process-wide configuration. Everything is overridable through env vars so
the same image behaves identically in `docker compose` and in tests."""
from __future__ import annotations

import os
from pathlib import Path


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


def _float(name: str, default: float) -> float:
    return float(os.environ.get(name, str(default)))


DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///" + str(Path(__file__).resolve().parent.parent / ".data" / "fota.db")
)
STORAGE_ROOT = Path(os.environ.get("STORAGE_ROOT", str(Path(__file__).resolve().parent.parent / ".data" / "artifacts")))

# Artifact is split into fixed-size blocks; resume works at block granularity.
CHUNK_SIZE = _int("CHUNK_SIZE", 256 * 1024)

# A batch is auto-halted when failures/max(1, terminal_attempts) >= threshold
# and at least FAILURE_MIN_SAMPLE attempts have reached a terminal state.
FAILURE_THRESHOLD = _float("FAILURE_THRESHOLD", 0.2)
FAILURE_MIN_SAMPLE = _int("FAILURE_MIN_SAMPLE", 3)

# Seed a demo image on first boot (used by scripts/demo.sh).
SEED_DEMO = os.environ.get("SEED_DEMO", "false").lower() in ("1", "true", "yes")

# Notary (transparency log) signing key. Like the demo release keys it lives
# next to the DB so a restart keeps the same pinned key; in production the
# private half stays in an HSM/KMS and only the public key is shipped.
NOTARY_KEYS_PATH = Path(
    os.environ.get("NOTARY_KEYS_PATH", str(Path(STORAGE_ROOT).parent / "notary_keys.json"))
)

# Crash-injection seam (tests only): when set, the log append transaction dies
# immediately after the ledger rows are flushed and before the transaction
# commits — proving no "claimable but not in the ledger" intermediate state.
CRASH_AFTER_LEAF_FLUSH = os.environ.get("CRASH_AFTER_LEAF_FLUSH", "")[:64]
