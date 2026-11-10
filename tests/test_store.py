"""Objects round-trip. Truncation, oversize, and a flipped byte are refused."""

import hashlib
import tempfile
from pathlib import Path

import pytest

from pebble.errors import AuthenticationError, FormatError
from pebble.store import META_MAX, STORED_CHUNK_MAX, Kind, Store


def test_write_and_read(tmp_path: Path) -> None:
    store = Store(tmp_path)
    payload = b"the object bytes"
    object_id = store.put(payload, kind=Kind.META)
    assert object_id == hashlib.sha256(payload).hexdigest()
    assert store.get(object_id, kind=Kind.META) == payload
    assert store.put(payload, kind=Kind.META) == object_id


def test_truncated_object_is_refused(tmp_path: Path) -> None:
    store = Store(tmp_path)
    payload = b"hello pebble object"
    object_id = store.put(payload, kind=Kind.META)
    path = store._path(object_id)

    path.write_bytes(b"")
    with pytest.raises(FormatError, match="truncated"):
        store.get(object_id, kind=Kind.META)

    path.write_bytes(payload[:-1])
    with pytest.raises(AuthenticationError, match="^authentication failed$"):
        store.get(object_id, kind=Kind.META)


def test_oversize_is_refused_before_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = Store(tmp_path)
    with pytest.raises(FormatError, match="too large"):
        store.put(b"x" * (STORED_CHUNK_MAX + 1), kind=Kind.CHUNK)
    with pytest.raises(FormatError, match="too large"):
        store.put(b"y" * (META_MAX + 1), kind=Kind.META)

    object_id = "ab" * 32
    path = store._path(object_id)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"z" * (STORED_CHUNK_MAX + 1))

    def refuse_read(_path: Path) -> bytes:
        raise AssertionError("read an oversize object")

    monkeypatch.setattr(store, "_read_all", refuse_read)
    with pytest.raises(FormatError, match="too large"):
        store.get(object_id, kind=Kind.CHUNK)


def test_flipped_byte_is_refused(tmp_path: Path) -> None:
    store = Store(tmp_path)
    object_id = store.put(b"intact", kind=Kind.CHUNK)
    path = store._path(object_id)
    flipped = bytearray(path.read_bytes())
    flipped[0] ^= 0x01
    path.write_bytes(bytes(flipped))
    with pytest.raises(AuthenticationError, match="^authentication failed$"):
        store.get(object_id, kind=Kind.CHUNK)


def test_bad_object_id_is_refused(tmp_path: Path) -> None:
    store = Store(tmp_path)
    with pytest.raises(FormatError, match="object id"):
        store.get("../" + "ab" * 28, kind=Kind.META)
    with pytest.raises(FormatError, match="missing"):
        store.get("ab" * 32, kind=Kind.META)


def test_temp_directory_is_removed() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        store = Store(root)
        object_id = store.put(b"temp", kind=Kind.CHUNK)
        assert store.get(object_id, kind=Kind.CHUNK) == b"temp"
        assert root.is_dir()
    assert not Path(name).exists()
