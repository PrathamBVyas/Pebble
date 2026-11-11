"""A fork receipt.

The receipt holds two signed commits. Each commit already carries the public
key it was signed under, so a checker needs no vault password and no file
key. The receipt shows that two histories diverged. It does not say who
moved the folder.
"""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
from pathlib import Path

from pebble.commit import verify_commit
from pebble.errors import FormatError

MAGIC = b"PRCP"
VERSION = 1


def write_receipt(path: Path, left: bytes, right: bytes) -> None:
    """Write a receipt. Both blobs must already be signed commits that diverged."""
    verify_receipt_bytes(_pack(left, right))
    _atomic_write(path, _pack(left, right))


def verify_receipt_bytes(blob: bytes) -> tuple[str, str]:
    """Check both signatures and that neither commit is the other's parent.

    Returns the two commit ids.
    """
    if isinstance(blob, str) or not isinstance(blob, (bytes, bytearray)):
        raise TypeError("receipt must be bytes")
    data = bytes(blob)
    if len(data) < 5 or data[:4] != MAGIC or data[4] != VERSION:
        raise FormatError("not a pebble receipt")
    left, pos = _frame(data, 5)
    right, pos = _frame(data, pos)
    if pos != len(data):
        raise FormatError("receipt is not valid")
    left_commit = verify_commit(left)
    right_commit = verify_commit(right)
    left_id = hashlib.sha256(left).hexdigest()
    right_id = hashlib.sha256(right).hexdigest()
    if left_id == right_id:
        raise FormatError("not a fork")
    left_parents = {parent.hex() for parent in left_commit.parents}
    right_parents = {parent.hex() for parent in right_commit.parents}
    if left_id in right_parents or right_id in left_parents:
        raise FormatError("not a fork")
    return left_id, right_id


def verify_receipt(path: Path) -> tuple[str, str]:
    """Read a receipt file and check it. No password is used."""
    return verify_receipt_bytes(Path(path).read_bytes())


def _pack(left: bytes, right: bytes) -> bytes:
    return (
        MAGIC
        + bytes([VERSION])
        + struct.pack(">I", len(left))
        + bytes(left)
        + struct.pack(">I", len(right))
        + bytes(right)
    )


def _frame(data: bytes, pos: int) -> tuple[bytes, int]:
    if pos + 4 > len(data):
        raise FormatError("receipt is truncated")
    length = struct.unpack(">I", data[pos : pos + 4])[0]
    start = pos + 4
    if length < 1 or start + length > len(data):
        raise FormatError("receipt is truncated")
    return data[start : start + length], start + length


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".pebble-tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
