"""Append-only view notes.

A note says the device has seen one save. The log lives outside the cipher
directory, so the folder provider cannot drop a note by replacing the folder.
Records are only appended. A torn tail from a crash is ignored. A complete
record with a bad signature is refused.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from pebble.errors import AuthenticationError, FormatError
from pebble.sign import SIGNATURE_LEN, verify

MAGIC = b"PVW1"
VERSION = 1
HASH_LEN = 32
_BODY_LEN = 4 + 1 + HASH_LEN + HASH_LEN
RECORD_LEN = _BODY_LEN + SIGNATURE_LEN


def append_view(log: Path, head: str, author: bytes, signer) -> None:
    """Append one signed note. signer(message) returns 64 bytes."""
    digest = _head(head)
    if not isinstance(author, (bytes, bytearray)) or len(author) != HASH_LEN:
        raise FormatError("witness author is not valid")
    body = MAGIC + bytes([VERSION]) + digest + bytes(author)
    signature = signer(body)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_LEN:
        raise FormatError("witness signature is not valid")
    framed = struct.pack(">I", RECORD_LEN) + body + bytes(signature)
    log.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(log, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        view = memoryview(framed)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def read_views(log: Path, *, required: bool) -> list[str]:
    """Return the save hashes in the log, oldest first.

    A missing log is an error when required is true. An empty file means the
    device has a log and has seen nothing.
    """
    if not log.is_file():
        if required:
            raise FormatError("witness log is missing")
        return []
    data = log.read_bytes()
    heads: list[str] = []
    pos = 0
    while pos + 4 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        start = pos + 4
        if start + length > len(data):
            break
        if length != RECORD_LEN:
            raise FormatError("witness log is not valid")
        record = data[start : start + length]
        pos = start + length
        heads.append(_open_record(record))
    return heads


def _open_record(record: bytes) -> str:
    if record[:4] != MAGIC or record[4] != VERSION:
        raise FormatError("witness log is not valid")
    body = record[:_BODY_LEN]
    signature = record[_BODY_LEN:]
    author = record[5 + HASH_LEN : 5 + HASH_LEN + HASH_LEN]
    try:
        verify(author, signature, body)
    except AuthenticationError:
        raise AuthenticationError() from None
    return record[5 : 5 + HASH_LEN].hex()


def _head(head: str) -> bytes:
    if not isinstance(head, str) or len(head) != 64:
        raise FormatError("witness head is not valid")
    if any(char not in "0123456789abcdef" for char in head):
        raise FormatError("witness head is not valid")
    return bytes.fromhex(head)
