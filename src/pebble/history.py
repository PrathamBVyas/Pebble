"""The three-way rule, and a merge of two directories.

classify does not read the disk. The caller passes the parent links it has
already loaded. A tip is an update when every accepted head and every
witnessed head is that tip or an ancestor of it. A tip is a rewind when it
sits strictly behind one of those heads. Any other shape is a split.

merge_dirs unions entries that changed on only one side. It builds nothing
when both sides changed the same file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pebble.commit import create_commit
from pebble.errors import MergeConflict
from pebble.tree import Dir

_YES = "yes"
_NO = "no"
_UNKNOWN = "unknown"
_WALK_LIMIT = 10_000


@dataclass(frozen=True)
class Verdict:
    """What to do with the tips the caller presented."""

    kind: Literal["update", "rewind", "split"]
    head: str
    others: tuple[str, ...] = ()


def classify(
    *,
    accepted: set[str],
    witnessed: set[str],
    tips: set[str],
    parents: dict[str, tuple[str, ...]],
) -> Verdict:
    """Decide update, rewind, or split from hashes the caller already has."""
    if not tips:
        raise ValueError("no tips")
    maximal = [
        tip
        for tip in sorted(tips)
        if not any(other != tip and _reaches(other, tip, parents) == _YES for other in tips)
    ]
    if len(maximal) != 1:
        return Verdict("split", _fallback(accepted, parents, maximal[0]), tuple(maximal))
    tip = maximal[0]
    anchors = set(accepted) | set(witnessed)
    if not anchors:
        return Verdict("update", tip, ())
    forks: list[str] = []
    ahead: list[str] = []
    for anchor in sorted(anchors):
        if _reaches(tip, anchor, parents) == _YES:
            continue
        if _reaches(anchor, tip, parents) == _YES:
            ahead.append(anchor)
            continue
        forks.append(anchor)
    if forks:
        return Verdict("split", _fallback(accepted, parents, tip), tuple(forks))
    if ahead:
        return Verdict("rewind", _fallback(set(ahead), parents, ahead[0]), (tip,))
    return Verdict("update", tip, ())


def merge_dirs(base: Dir, left: Dir, right: Dir) -> Dir:
    """Union changes that happened on only one side. Conflict leaves no tree."""
    return _merge(base, left, right)


def merge_commit(
    *,
    base: Dir,
    left: Dir,
    right: Dir,
    left_id: str,
    right_id: str,
    listing: str,
    seed: bytes,
) -> tuple[Dir, bytes]:
    """Merge the trees, then sign a commit with both parents.

    The listing id is the caller's. This function does not write it.
    """
    merged = merge_dirs(base, left, right)
    blob = create_commit(parents=(left_id, right_id), listing=listing, seed=seed)
    return merged, blob


def _merge(base: Dir, left: Dir, right: Dir) -> Dir:
    result = Dir()
    names = (
        set(base.files)
        | set(base.dirs)
        | set(left.files)
        | set(left.dirs)
        | set(right.files)
        | set(right.dirs)
    )
    for name in sorted(names):
        merged = _merge_entry(_lookup(base, name), _lookup(left, name), _lookup(right, name))
        if isinstance(merged, Dir):
            result.dirs[name] = merged
        elif isinstance(merged, bytes):
            result.files[name] = merged
    return result


def _merge_entry(base: object, left: object, right: object) -> Dir | bytes | None:
    if _same(left, right):
        return _copy(left)
    if _same(left, base):
        return _copy(right)
    if _same(right, base):
        return _copy(left)
    if (
        isinstance(left, Dir)
        and isinstance(right, Dir)
        and (base is None or isinstance(base, Dir))
    ):
        return _merge(base if isinstance(base, Dir) else Dir(), left, right)
    raise MergeConflict()


def _lookup(directory: Dir, name: str) -> Dir | bytes | None:
    if name in directory.files and name in directory.dirs:
        raise MergeConflict()
    if name in directory.files:
        return directory.files[name]
    if name in directory.dirs:
        return directory.dirs[name]
    return None


def _same(left: object, right: object) -> bool:
    return _snapshot(left) == _snapshot(right)


@dataclass(frozen=True)
class _FileSnap:
    data: bytes


@dataclass(frozen=True)
class _DirSnap:
    files: tuple[tuple[str, bytes], ...]
    dirs: tuple[tuple[str, "_DirSnap"], ...]


def _snapshot(value: object) -> _FileSnap | _DirSnap | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return _FileSnap(bytes(value))
    if isinstance(value, Dir):
        files = tuple(sorted((name, bytes(data)) for name, data in value.files.items()))
        dirs = tuple(sorted((name, _dir_snap(child)) for name, child in value.dirs.items()))
        return _DirSnap(files, dirs)
    raise TypeError("merge entry must be a file or a directory")


def _dir_snap(directory: Dir) -> _DirSnap:
    snap = _snapshot(directory)
    assert isinstance(snap, _DirSnap)
    return snap


def _copy(value: object) -> Dir | bytes | None:
    snap = _snapshot(value)
    if snap is None:
        return None
    if isinstance(snap, _FileSnap):
        return snap.data
    return _copy_dir(snap)


def _copy_dir(snap: _DirSnap) -> Dir:
    directory = Dir()
    for name, data in snap.files:
        directory.files[name] = data
    for name, child in snap.dirs:
        directory.dirs[name] = _copy_dir(child)
    return directory


def _reaches(start: str, goal: str, parents: dict[str, tuple[str, ...]]) -> str:
    """Whether goal is start, or an ancestor of start. Unknown if a link is missing."""
    if start == goal:
        return _YES
    seen: set[str] = set()
    stack = [start]
    missing = False
    while stack:
        if len(seen) > _WALK_LIMIT:
            return _UNKNOWN
        node = stack.pop()
        if node in seen:
            continue
        if node == goal:
            return _YES
        seen.add(node)
        if node not in parents:
            # Another parent of a merge may still reach the goal.
            missing = True
            continue
        stack.extend(parents[node])
    if missing:
        return _UNKNOWN
    return _NO


def _fallback(anchors: set[str], parents: dict[str, tuple[str, ...]], default: str) -> str:
    chosen = _preferred(anchors, parents)
    if chosen is not None:
        return chosen
    if anchors:
        return sorted(anchors)[0]
    return default


def _preferred(anchors: set[str], parents: dict[str, tuple[str, ...]]) -> str | None:
    if not anchors:
        return None
    if len(anchors) == 1:
        return next(iter(anchors))
    maximal = [
        item
        for item in sorted(anchors)
        if not any(
            other != item and _reaches(other, item, parents) == _YES for other in anchors
        )
    ]
    if len(maximal) == 1:
        return maximal[0]
    return None
