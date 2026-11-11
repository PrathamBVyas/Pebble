"""Two files survive a reload. Bad names, a deep chain, and a moved chunk do not."""

import secrets
import struct
from pathlib import Path

import pytest

from pebble.errors import AuthenticationError, FormatError
from pebble.store import PLAIN_CHUNK_MAX, Kind, Store
from pebble.tree import (
    MAX_DEPTH,
    LISTING_AAD,
    Entry,
    Dir,
    _pack,
    _put_chunk,
    _store_listing,
    decode_listing,
    load,
    open_listing,
    save,
)
from pebble.aead import encrypt


def test_two_files_survive_a_reload(tmp_path: Path) -> None:
    store = Store(tmp_path)
    key = secrets.token_bytes(32)
    directory = Dir()
    directory.files["one"] = b"alpha"
    directory.files["two"] = b"beta"
    listing_id = save(store, directory, key)

    loaded = load(Store(tmp_path), listing_id, key)
    assert loaded.files == {"one": b"alpha", "two": b"beta"}
    stored = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    assert b"alpha" not in stored
    assert b"beta" not in stored


def test_nested_directory_and_empty_file_round_trip(tmp_path: Path) -> None:
    store = Store(tmp_path)
    key = secrets.token_bytes(32)
    child = Dir()
    child.files["note"] = b"inside"
    root = Dir()
    root.dirs["sub"] = child
    root.files["empty"] = b""
    listing_id = save(store, root, key)
    loaded = load(store, listing_id, key)
    assert loaded.files == {"empty": b""}
    assert loaded.dirs["sub"].files == {"note": b"inside"}


def test_file_larger_than_one_chunk_round_trips(tmp_path: Path) -> None:
    store = Store(tmp_path)
    key = secrets.token_bytes(32)
    payload = b"q" * (PLAIN_CHUNK_MAX + 1)
    directory = Dir()
    directory.files["big"] = payload
    listing_id = save(store, directory, key)
    assert load(store, listing_id, key).files["big"] == payload


@pytest.mark.parametrize("name", ["a/b", "a\x00b", ".", "..", "...", "n" * 256])
def test_bad_name_is_refused(tmp_path: Path, name: str) -> None:
    store = Store(tmp_path)
    directory = Dir()
    directory.files[name] = b"x"
    with pytest.raises(FormatError, match="name is not valid"):
        save(store, directory, secrets.token_bytes(32))


def test_name_of_255_bytes_is_kept(tmp_path: Path) -> None:
    store = Store(tmp_path)
    key = secrets.token_bytes(32)
    name = "n" * 255
    directory = Dir()
    directory.files[name] = b"ok"
    listing_id = save(store, directory, key)
    assert load(store, listing_id, key).files[name] == b"ok"


def test_depth_past_32_is_refused(tmp_path: Path) -> None:
    store = Store(tmp_path)
    key = secrets.token_bytes(32)
    allowed = _nest(MAX_DEPTH)
    _deepest(allowed).files["note"] = b"deep"
    listing_id = save(store, allowed, key)
    assert _deepest(load(store, listing_id, key)).files["note"] == b"deep"

    with pytest.raises(FormatError, match="too deep"):
        save(store, _nest(MAX_DEPTH + 1), key)


def test_hostile_depth_is_refused_on_load(tmp_path: Path) -> None:
    store = Store(tmp_path)
    leaf_key = secrets.token_bytes(32)
    current_id = _store_listing(store, leaf_key, [])
    current_key = leaf_key
    for _ in range(MAX_DEPTH + 1):
        parent_key = secrets.token_bytes(32)
        row = Entry(b"d", 2, current_key, (bytes.fromhex(current_id),))
        current_id = _store_listing(store, parent_key, [row])
        current_key = parent_key
    with pytest.raises(FormatError, match="too deep"):
        load(store, current_id, current_key)


def test_hostile_name_is_refused_after_the_tag(tmp_path: Path) -> None:
    store = Store(tmp_path)
    key = secrets.token_bytes(32)
    row = Entry(b"..", 1, secrets.token_bytes(32), ())
    listing_id = _store_listing(store, key, [row])
    with pytest.raises(FormatError, match="name is not valid"):
        load(store, listing_id, key)


def test_huge_entry_count_is_refused_before_the_loop(tmp_path: Path) -> None:
    store = Store(tmp_path)
    key = secrets.token_bytes(32)
    plain = b"PLST\x01" + struct.pack(">I", 0xFFFFFFFF) + b"\x00" * 4
    listing_id = store.put(encrypt(key, plain, LISTING_AAD), kind=Kind.META)
    with pytest.raises(FormatError, match="too large"):
        load(store, listing_id, key)


def test_tag_is_checked_before_listing_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    key = secrets.token_bytes(32)
    blob = bytearray(encrypt(key, _pack([]), LISTING_AAD))
    blob[-1] ^= 0x01

    def explode(_plain: bytes) -> tuple[Entry, ...]:
        raise AssertionError("parsed a listing before the tag")

    monkeypatch.setattr("pebble.tree.decode_listing", explode)
    with pytest.raises(AuthenticationError, match="^authentication failed$"):
        open_listing(bytes(blob), key)


def test_swapped_chunk_is_refused(tmp_path: Path) -> None:
    store = Store(tmp_path)
    listing_key = secrets.token_bytes(32)
    file_key = secrets.token_bytes(32)
    first = _put_chunk(store, file_key, b"A" * 8, 0)
    second = _put_chunk(store, file_key, b"B" * 8, 1)
    row = Entry(b"f", 1, file_key, (second, first))
    listing_id = _store_listing(store, listing_key, [row])
    with pytest.raises(AuthenticationError):
        load(store, listing_id, listing_key)


def test_truncated_listing_plaintext_is_refused() -> None:
    # The declared name is longer than the bytes that follow, but the entry
    # count still fits in the buffer, so this is truncation rather than a huge count.
    body = struct.pack(">H", 30) + b"a" * 38
    plain = b"PLST\x01" + struct.pack(">I", 1) + body
    with pytest.raises(FormatError, match="truncated"):
        decode_listing(plain)


def _nest(levels: int) -> Dir:
    root = Dir()
    cursor = root
    for _ in range(levels):
        child = Dir()
        cursor.dirs["d"] = child
        cursor = child
    return root


def _deepest(directory: Dir) -> Dir:
    cursor = directory
    while cursor.dirs:
        cursor = cursor.dirs["d"]
    return cursor
