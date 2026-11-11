"""Signed commits, stored in the clear.

The signed bytes are the parent hashes, the listing hash, and the author
public key. The Ed25519 signature is checked before those fields are
returned, so a bad signature does not become a parent pointer. Nothing
here decides whether a commit is an update, a rewind, or a split.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pebble.errors import FormatError
from pebble.sign import SIGNATURE_LEN, public_key, sign, verify
from pebble.store import Kind, Store

MAGIC = b"PCMT"
VERSION = 1
HASH_LEN = 32
MAX_PARENTS = 2


@dataclass(frozen=True)
class Commit:
    """A verified commit. parents and listing are raw SHA-256 digests."""

    parents: tuple[bytes, ...]
    listing: bytes
    author: bytes
    signature: bytes


def create_commit(*, parents: Sequence[str], listing: str, seed: bytes) -> bytes:
    """Sign a commit. parents and listing are lowercase hex object ids."""
    raw_parents = tuple(_object_id(parent) for parent in parents)
    if len(raw_parents) > MAX_PARENTS:
        raise FormatError("commit has too many parents")
    body = _body(raw_parents, _object_id(listing), public_key(seed))
    return body + sign(seed, body)


def verify_commit(blob: bytes) -> Commit:
    """Check the signature, then return the commit. A bad signature raises."""
    if isinstance(blob, str) or not isinstance(blob, (bytes, bytearray)):
        raise TypeError("commit must be bytes")
    data = bytes(blob)
    if len(data) < 4 or data[:4] != MAGIC:
        raise FormatError("not a pebble commit")
    if len(data) < 6 or data[4] != VERSION:
        raise FormatError("commit is not valid")
    parent_count = data[5]
    if parent_count > MAX_PARENTS:
        raise FormatError("commit has too many parents")
    body_len = 6 + parent_count * HASH_LEN + HASH_LEN + HASH_LEN
    if len(data) < body_len + SIGNATURE_LEN:
        raise FormatError("commit is truncated")
    if len(data) != body_len + SIGNATURE_LEN:
        raise FormatError("commit is not valid")
    body = data[:body_len]
    signature = data[body_len:]
    author = body[-HASH_LEN:]
    verify(author, signature, body)
    parents = tuple(
        body[6 + index * HASH_LEN : 6 + (index + 1) * HASH_LEN]
        for index in range(parent_count)
    )
    listing_at = 6 + parent_count * HASH_LEN
    listing = body[listing_at : listing_at + HASH_LEN]
    return Commit(parents, listing, author, signature)


def load_commit(store: Store, object_id: str) -> Commit:
    """Read one commit and verify it before returning."""
    return verify_commit(store.get(object_id, kind=Kind.META))


def lineage(store: Store, tip: str) -> tuple[Commit, ...]:
    """Verified commits from the tip back to the root, along the first parent."""
    found: list[Commit] = []
    seen: set[str] = set()
    current = tip
    while True:
        if current in seen:
            raise FormatError("commit chain is cyclic")
        seen.add(current)
        commit = load_commit(store, current)
        found.append(commit)
        if not commit.parents:
            return tuple(found)
        current = commit.parents[0].hex()


def _body(parents: tuple[bytes, ...], listing: bytes, author: bytes) -> bytes:
    out = bytearray(MAGIC)
    out.append(VERSION)
    out.append(len(parents))
    for parent in parents:
        out += parent
    out += listing
    out += author
    return bytes(out)


def _object_id(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != HASH_LEN * 2:
        raise FormatError("object id is not valid")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise FormatError("object id is not valid") from exc
    if raw.hex() != value:
        raise FormatError("object id is not valid")
    return raw
