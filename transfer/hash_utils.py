from __future__ import annotations

import hashlib
from pathlib import Path


def calculate_sha256(
    file_path: str | Path,
    read_size: int = 1024 * 1024,
) -> str:
    if read_size <= 0:
        raise ValueError("read_size must be positive")

    digest = hashlib.sha256()
    with Path(file_path).open("rb") as source:
        while chunk := source.read(read_size):
            digest.update(chunk)
    return digest.hexdigest()
