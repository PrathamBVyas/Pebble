"""A directory tree that keeps file keys across saves.

An ordinary save reuses a file key and the chunk ids of a file that did not
change. Revoke replaces one folder's listing key and leaves every file key
where it was, so the old ciphertext stays readable to someone who already
has it and the new listing is not.
"""

from __future__ import annotations

import secrets

from pebble.secret import wipe_buffer
from pebble.store import Kind, Store
from pebble.tree import (
    Dir,
    Entry,
    _DIR,
    _FILE,
    _read_chunks,
    _store_listing,
    _write_chunks,
    open_listing,
)


class FileMeta:
    """The key and chunk ids for one file. The bytes live on the directory."""

    def __init__(self, key: bytes, parts: tuple[bytes, ...], dirty: bool) -> None:
        self.key = bytearray(key)
        self.parts = parts
        self.dirty = dirty


class VDir(Dir):
    """A directory whose listing key survives an ordinary save."""

    def __init__(self, key: bytes, listing_id: str | None = None) -> None:
        super().__init__()
        self.key = bytearray(key)
        self.listing_id = listing_id
        self.meta: dict[str, FileMeta] = {}
        self.dirty = False

    def add_file(self, name: str, data: bytes) -> bytearray:
        body = bytearray(data)
        self.files[name] = body
        self.meta[name] = FileMeta(secrets.token_bytes(32), (), True)
        self.dirty = True
        return body

    def touch(self, name: str) -> None:
        self.meta[name].dirty = True
        self.dirty = True

    def add_dir(self, name: str) -> "VDir":
        child = VDir(secrets.token_bytes(32))
        child.dirty = True
        self.dirs[name] = child
        self.dirty = True
        return child

    def drop_file(self, name: str) -> bytearray:
        body = self.files.pop(name)
        meta = self.meta.pop(name)
        wipe_buffer(meta.key)
        self.dirty = True
        return body

    def move_file(self, name: str, dest: "VDir", new_name: str) -> bytearray:
        body = self.files.pop(name)
        meta = self.meta.pop(name)
        dest.files[new_name] = body
        dest.meta[new_name] = meta
        meta.dirty = True
        dest.dirty = True
        self.dirty = True
        return body


def load_volume(store: Store, listing_id: str, key: bytes) -> VDir:
    """Decrypt a listing tree and remember the keys it already uses."""
    node = VDir(key, listing_id)
    blob = store.get(listing_id, kind=Kind.META)
    for entry in open_listing(blob, bytes(node.key)):
        name = entry.name.decode("utf-8")
        if entry.kind == _DIR:
            child = load_volume(store, entry.parts[0].hex(), entry.key)
            node.dirs[name] = child
        else:
            material = bytearray(entry.key)
            try:
                node.files[name] = bytearray(_read_chunks(store, material, entry.parts))
            finally:
                wipe_buffer(material)
            node.meta[name] = FileMeta(entry.key, entry.parts, False)
    return node


def store_volume(store: Store, node: VDir, *, sync: bool = True) -> str:
    """Write dirty listings. Unchanged files keep their chunk ids and keys."""
    if not _needs_write(node) and node.listing_id:
        return node.listing_id
    rows: list[Entry] = []
    for name in sorted(node.dirs):
        child = node.dirs[name]
        if not isinstance(child, VDir):
            raise TypeError("directory entry must be a VDir")
        child_id = store_volume(store, child, sync=sync)
        rows.append(Entry(name.encode("utf-8"), _DIR, bytes(child.key), (bytes.fromhex(child_id),)))
    for name in sorted(node.files):
        meta = node.meta[name]
        if meta.dirty or not meta.parts:
            meta.parts = _write_chunks(store, bytes(meta.key), bytes(node.files[name]), sync)
            meta.dirty = False
        rows.append(Entry(name.encode("utf-8"), _FILE, bytes(meta.key), meta.parts))
    rows.sort(key=lambda row: row.name)
    node.listing_id = _store_listing(store, bytes(node.key), rows, sync)
    node.dirty = False
    return node.listing_id


def wipe_volume(node: VDir) -> None:
    """Wipe listing keys, file keys, and file bodies."""
    wipe_buffer(node.key)
    for meta in node.meta.values():
        wipe_buffer(meta.key)
    for name, data in list(node.files.items()):
        if isinstance(data, bytearray):
            wipe_buffer(data)
        node.files[name] = b""
    for child in node.dirs.values():
        if isinstance(child, VDir):
            wipe_volume(child)


def walk(node: VDir, path: str) -> VDir:
    """Return the directory at path. An empty path is the node itself."""
    current = node
    if path:
        for part in path.split("/"):
            child = current.dirs.get(part)
            if not isinstance(child, VDir):
                raise KeyError(path)
            current = child
    return current


def _needs_write(node: VDir) -> bool:
    if node.dirty or node.listing_id is None:
        return True
    if any(meta.dirty for meta in node.meta.values()):
        return True
    return any(isinstance(child, VDir) and _needs_write(child) for child in node.dirs.values())
