"""Content-addressed object store.

Each object is one file. The file name is the SHA-256 of those bytes, so a
flipped or shortened file no longer matches its name. Chunk objects are at
most 64 KiB of plaintext plus the AEAD overhead. Metadata objects, such as
listings and commits, are at most 1 MiB. The size on disk is checked before
the file is read, and therefore before anything parses it.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from enum import Enum
from pathlib import Path

from pebble.aead import NONCE_LEN, TAG_LEN
from pebble.errors import AuthenticationError, FormatError

PLAIN_CHUNK_MAX = 64 * 1024
STORED_CHUNK_MAX = PLAIN_CHUNK_MAX + NONCE_LEN + TAG_LEN
META_MAX = 1 * 1024 * 1024


class Kind(Enum):
    """Which size cap an object is measured against."""

    CHUNK = "chunk"
    META = "meta"


_LIMIT = {
    Kind.CHUNK: STORED_CHUNK_MAX,
    Kind.META: META_MAX,
}


class Store:
    """A directory of objects. The caller chooses the root."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes, *, kind: Kind) -> str:
        """Store data and return its hex SHA-256. Oversize data is refused."""
        if isinstance(data, str) or not isinstance(data, (bytes, bytearray)):
            raise TypeError("object must be bytes")
        body = bytes(data)
        if len(body) > _LIMIT[kind]:
            raise FormatError("object is too large")
        object_id = hashlib.sha256(body).hexdigest()
        path = self._path(object_id)
        if self._same_file(path, body):
            return object_id
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        _fsync_dir(path.parent)
        return object_id

    def get(self, object_id: str, *, kind: Kind) -> bytes:
        """Return the object. Size, truncation, and the hash are checked first."""
        path = self._path(_check_id(object_id))
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise FormatError("object is missing") from None
        if not stat.S_ISREG(info.st_mode):
            raise FormatError("object is missing")
        if info.st_size > _LIMIT[kind]:
            raise FormatError("object is too large")
        if info.st_size == 0:
            raise FormatError("object is truncated")
        data = self._read_all(path)
        if len(data) != info.st_size or len(data) > _LIMIT[kind]:
            raise FormatError("object is truncated")
        if hashlib.sha256(data).hexdigest() != object_id:
            raise AuthenticationError()
        return data

    def _path(self, object_id: str) -> Path:
        return self.root / object_id[:2] / object_id[2:]

    def _read_all(self, path: Path) -> bytes:
        return path.read_bytes()

    @staticmethod
    def _same_file(path: Path, body: bytes) -> bool:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_size != len(body):
            return False
        return path.read_bytes() == body


def _check_id(object_id: str) -> str:
    if not isinstance(object_id, str) or len(object_id) != 64:
        raise FormatError("object id is not valid")
    if any(char not in "0123456789abcdef" for char in object_id):
        raise FormatError("object id is not valid")
    return object_id


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
