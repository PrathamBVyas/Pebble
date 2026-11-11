"""Encrypted files and the directory listing that points at them.

A file is split into 64 KiB chunks. Each chunk is sealed with the file's
data key, and the tag covers the chunk index, so a chunk cannot be moved
to another position. A directory listing is sealed with that directory's
key. The listing holds child names and child keys. The authentication tag
is checked before any plaintext field is read.

Names are at most 255 bytes. `/`, NUL, `.`, `..`, and `...` are refused.
A directory chain deeper than 32 is refused.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from pebble.aead import NONCE_LEN, TAG_LEN, decrypt, encrypt
from pebble.errors import FormatError
from pebble.secret import wipe_buffer
from pebble.store import META_MAX, PLAIN_CHUNK_MAX, Kind, Store

LISTING_AAD = b"pebble-listing-v1"
_CHUNK_AAD = b"pebble-chunk-v1"
_MAGIC = b"PLST"
_VERSION = 1
_FILE = 1
_DIR = 2
MAX_DEPTH = 32
MAX_NAME = 255
_FORBIDDEN = {b".", b"..", b"..."}
# name length, one name byte, kind, key, part count
_MIN_ENTRY = 2 + 1 + 1 + 32 + 2


class Dir:
    """A plain directory. Files map a name to bytes. Subdirectories nest."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.dirs: dict[str, Dir] = {}


@dataclass(frozen=True)
class Entry:
    """One decoded listing row. Produced only after the tag has been checked."""

    name: bytes
    kind: int
    key: bytes
    parts: tuple[bytes, ...]


def save(store: Store, directory: Dir, key: bytes, *, sync: bool = True) -> str:
    """Seal a directory tree. Returns the root listing's object id.

    sync=False writes the objects and leaves one later Store.sync to the caller.
    """
    _preflight(directory, 0)
    return _save(store, directory, key, 0, sync)


def load(store: Store, listing_id: str, key: bytes) -> Dir:
    """Open a listing that save wrote. The same key is required."""
    return _load(store, listing_id, key, 0)


def open_listing(blob: bytes, key: bytes) -> tuple[Entry, ...]:
    """Decrypt a listing blob, then parse it. A bad tag never reaches the parser."""
    plain = decrypt(key, blob, LISTING_AAD)
    return decode_listing(plain)


def decode_listing(plain: bytes) -> tuple[Entry, ...]:
    """Parse listing plaintext. Call this only after the tag has verified."""
    if len(plain) < 9 or plain[:4] != _MAGIC or plain[4] != _VERSION:
        raise FormatError("listing is not valid")
    count = struct.unpack(">I", plain[5:9])[0]
    if count > (len(plain) - 9) // _MIN_ENTRY:
        raise FormatError("listing is too large")
    entries: list[Entry] = []
    seen: set[bytes] = set()
    pos = 9
    for _ in range(count):
        if pos + 2 > len(plain):
            raise FormatError("listing is truncated")
        name_len = struct.unpack(">H", plain[pos : pos + 2])[0]
        pos += 2
        if name_len < 1 or name_len > MAX_NAME:
            raise FormatError("name is not valid")
        if pos + name_len + 1 + 32 + 2 > len(plain):
            raise FormatError("listing is truncated")
        name = plain[pos : pos + name_len]
        pos += name_len
        _check_name(name)
        if name in seen:
            raise FormatError("name is not valid")
        seen.add(name)
        kind = plain[pos]
        pos += 1
        if kind not in (_FILE, _DIR):
            raise FormatError("listing is not valid")
        key = plain[pos : pos + 32]
        pos += 32
        part_count = struct.unpack(">H", plain[pos : pos + 2])[0]
        pos += 2
        if part_count > (len(plain) - pos) // 32:
            raise FormatError("listing is too large")
        if kind == _DIR and part_count != 1:
            raise FormatError("listing is not valid")
        parts = tuple(
            plain[pos + index * 32 : pos + (index + 1) * 32] for index in range(part_count)
        )
        pos += part_count * 32
        entries.append(Entry(name, kind, key, parts))
    if pos != len(plain):
        raise FormatError("listing is not valid")
    return tuple(entries)


def _save(store: Store, directory: Dir, key: bytes, depth: int, sync: bool) -> str:
    if depth > MAX_DEPTH:
        raise FormatError("directory is too deep")
    rows: list[Entry] = []
    for name in sorted(directory.dirs):
        child_key = secrets.token_bytes(32)
        child_id = _save(store, directory.dirs[name], child_key, depth + 1, sync)
        rows.append(Entry(_name_bytes(name), _DIR, child_key, (bytes.fromhex(child_id),)))
    for name in sorted(directory.files):
        file_key = secrets.token_bytes(32)
        parts = _write_chunks(store, file_key, bytes(directory.files[name]), sync)
        rows.append(Entry(_name_bytes(name), _FILE, file_key, parts))
    rows.sort(key=lambda row: row.name)
    return _store_listing(store, key, rows, sync)


def _load(store: Store, listing_id: str, key: bytes, depth: int) -> Dir:
    if depth > MAX_DEPTH:
        raise FormatError("directory is too deep")
    blob = store.get(listing_id, kind=Kind.META)
    directory = Dir()
    for entry in open_listing(blob, key):
        name = entry.name.decode("utf-8")
        material = bytearray(entry.key)
        try:
            if entry.kind == _DIR:
                child = _load(store, entry.parts[0].hex(), material, depth + 1)
                directory.dirs[name] = child
            else:
                directory.files[name] = _read_chunks(store, material, entry.parts)
        finally:
            wipe_buffer(material)
    return directory


def _store_listing(
    store: Store, key: bytes, entries: list[Entry] | tuple[Entry, ...], sync: bool = True
) -> str:
    plain = _pack(entries)
    if len(plain) + NONCE_LEN + TAG_LEN > META_MAX:
        raise FormatError("object is too large")
    blob = encrypt(key, plain, LISTING_AAD)
    return store.put(blob, kind=Kind.META, sync=sync)


def _pack(entries: list[Entry] | tuple[Entry, ...]) -> bytes:
    out = bytearray(_MAGIC)
    out.append(_VERSION)
    out += struct.pack(">I", len(entries))
    for entry in entries:
        if len(entry.key) != 32 or any(len(part) != 32 for part in entry.parts):
            raise FormatError("listing is not valid")
        out += struct.pack(">H", len(entry.name))
        out += entry.name
        out.append(entry.kind)
        out += entry.key
        out += struct.pack(">H", len(entry.parts))
        for part in entry.parts:
            out += part
    return bytes(out)


def _write_chunks(store: Store, key: bytes, plaintext: bytes, sync: bool) -> tuple[bytes, ...]:
    parts: list[bytes] = []
    offset = 0
    index = 0
    while offset < len(plaintext):
        block = plaintext[offset : offset + PLAIN_CHUNK_MAX]
        parts.append(_put_chunk(store, key, block, index, sync))
        offset += len(block)
        index += 1
    return tuple(parts)


def _put_chunk(store: Store, key: bytes, block: bytes, index: int, sync: bool = True) -> bytes:
    if len(block) > PLAIN_CHUNK_MAX:
        raise FormatError("chunk is too large")
    blob = encrypt(key, block, _chunk_aad(index))
    object_id = store.put(blob, kind=Kind.CHUNK, sync=sync)
    return bytes.fromhex(object_id)


def _read_chunks(store: Store, key: bytes, parts: tuple[bytes, ...]) -> bytes:
    pieces: list[bytes] = []
    for index, part in enumerate(parts):
        blob = store.get(part.hex(), kind=Kind.CHUNK)
        pieces.append(decrypt(key, blob, _chunk_aad(index)))
    return b"".join(pieces)


def _chunk_aad(index: int) -> bytes:
    return _CHUNK_AAD + index.to_bytes(4, "big")


def _preflight(directory: Dir, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise FormatError("directory is too deep")
    if not isinstance(directory, Dir):
        raise TypeError("directory entry must be a Dir")
    if set(directory.files) & set(directory.dirs):
        raise FormatError("name is not valid")
    for name in list(directory.files) + list(directory.dirs):
        _name_bytes(name)
    for content in directory.files.values():
        if isinstance(content, str) or not isinstance(content, (bytes, bytearray)):
            raise TypeError("file must be bytes")
    for child in directory.dirs.values():
        _preflight(child, depth + 1)


def _name_bytes(name: str | bytes) -> bytes:
    if isinstance(name, str):
        try:
            raw = name.encode("utf-8")
        except UnicodeError as exc:
            raise FormatError("name is not valid") from exc
    elif isinstance(name, (bytes, bytearray)):
        raw = bytes(name)
    else:
        raise TypeError("name must be text")
    _check_name(raw)
    return raw


def _check_name(raw: bytes) -> None:
    if not raw or len(raw) > MAX_NAME or raw in _FORBIDDEN or b"/" in raw or b"\x00" in raw:
        raise FormatError("name is not valid")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError("name is not valid") from exc
