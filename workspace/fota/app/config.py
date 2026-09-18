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

# Notary signing key for Merkle checkpoints. Lives next to the DB like the
# demo keys; production would hold it in an HSM/KMS and only expose the public
# half. Devices pin the public key on first contact (TOFU).
NOTARY_KEY_PATH = Path(
    os.environ.get("NOTARY_KEY_PATH", str(Path(STORAGE_ROOT).parent / "notary_key.json"))
)
