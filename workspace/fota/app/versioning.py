"""Loose version comparison: numeric segments compare numerically, other
segments lexicographically (good enough for semver-style and bootloader IDs)."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Image


def parse_version(v: str) -> tuple:
    out = []
    for seg in str(v).strip().split("."):
        try:
            out.append((0, int(seg)))
        except ValueError:
            out.append((1, seg))
    return tuple(out)


def compare(a: str, b: str) -> int:
    pa, pb = parse_version(a), parse_version(b)
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def compatible_bootloader(device_bootloader: str, image: "Image") -> bool:
    if image.min_bootloader and compare(device_bootloader, image.min_bootloader) < 0:
        return False
    if image.max_bootloader and compare(device_bootloader, image.max_bootloader) > 0:
        return False
    return True
