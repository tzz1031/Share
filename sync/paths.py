from __future__ import annotations

from pathlib import Path, PurePosixPath


INTERNAL_FOLDER = ".lan-sync"


def normalize_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("relative_path must be a non-empty string")
    if "\\" in value:
        raise ValueError("relative_path must use forward slashes")

    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("relative_path must stay inside the shared folder")
    if not path.parts or path.parts[0] == INTERNAL_FOLDER:
        raise ValueError("relative_path points to an internal file")
    return path.as_posix()


def destination_for(shared_folder: Path, relative_path: str) -> Path:
    normalized = normalize_relative_path(relative_path)
    root = shared_folder.resolve()
    destination = shared_folder.joinpath(*PurePosixPath(normalized).parts)
    resolved_parent = destination.parent.resolve()
    if not resolved_parent.is_relative_to(root):
        raise ValueError("relative_path escapes the shared folder")
    if destination.is_symlink():
        raise ValueError("relative_path points to a symbolic link")
    return destination


def should_ignore_path(shared_folder: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(shared_folder)
    except ValueError:
        return True

    if not relative.parts:
        return True
    if relative.parts[0] == INTERNAL_FOLDER:
        return True

    name = path.name
    return (
        name.startswith(".incoming-")
        or name.endswith(".part")
        or name.endswith(".tmp")
        or name.endswith(".state.json")
    )
