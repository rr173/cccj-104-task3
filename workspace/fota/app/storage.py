"""Content-addressed artifact store + fixed-size block manifest.

Uploaded firmware is hashed and cut into blocks. Each block is stored as
<sha256(block)>.part so a resuming client can independently verify every block
it already holds and only re-fetch missing/corrupt ones (trusted resume).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import config


@dataclass(frozen=True)
class StoredImage:
    sha256: str
    size: int
    chunk_size: int
    chunk_count: int
    chunk_sha: list[str]


def _img_dir(root: Path, image_sha: str) -> Path:
    d = root / image_sha[:2] / image_sha
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_blob(data: bytes, chunk_size: int | None = None) -> StoredImage:
    chunk_size = chunk_size or config.CHUNK_SIZE
    root = config.STORAGE_ROOT
    total = hashlib.sha256()
    chunk_hashes: list[str] = []
    for offset in range(0, len(data), chunk_size):
        block = data[offset:offset + chunk_size]
        chunk_hashes.append(hashlib.sha256(block).hexdigest())
        total.update(block)
    image_sha = total.hexdigest()
    image_dir = _img_dir(root, image_sha)
    for i, ch in enumerate(chunk_hashes):
        part = image_dir / f"{ch}.part"
        if not part.exists():
            part.write_bytes(data[i * chunk_size:(i + 1) * chunk_size])
    (image_dir / "manifest.json").write_text(
        json.dumps(
            {
                "sha256": image_sha,
                "size": len(data),
                "chunk_size": chunk_size,
                "chunk_count": len(chunk_hashes),
                "chunks": chunk_hashes,
            },
            indent=2,
        )
    )
    return StoredImage(image_sha, len(data), chunk_size, len(chunk_hashes), chunk_hashes)


def load_manifest(image_sha: str) -> StoredImage | None:
    mf = config.STORAGE_ROOT / image_sha[:2] / image_sha / "manifest.json"
    if not mf.exists():
        return None
    m = json.loads(mf.read_text())
    return StoredImage(m["sha256"], m["size"], m["chunk_size"], m["chunk_count"], m["chunks"])


def read_chunk(image_sha: str, index: int) -> bytes | None:
    m = load_manifest(image_sha)
    if m is None or not 0 <= index < m.chunk_count:
        return None
    part = config.STORAGE_ROOT / image_sha[:2] / image_sha / f"{m.chunk_sha[index]}.part"
    if not part.exists():
        return None
    return part.read_bytes()
