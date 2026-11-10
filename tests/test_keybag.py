"""Argon2id keybag: round-trip, a clear wrong password, and a wiped buffer."""

import struct
import time

import pytest
from argon2.low_level import Type, hash_secret_raw

from pebble.errors import CryptoError, FormatError, PasswordError
from pebble.keybag import (
    HEADER_LEN,
    KEYBAG_LEN,
    MEMORY_KIB,
    PARALLELISM,
    TIME_COST,
    Keybag,
    UnlockedKeybag,
    _argon2,
)
from pebble.seal import seal
from pebble.secret import wipe_buffer
from pebble.sign import verify

PASSWORD = b"correct horse battery staple"


@pytest.fixture(scope="module")
def created() -> dict[str, object]:
    blob, opened = Keybag.create(bytearray(PASSWORD))
    message = b"commit body"
    signature = opened.sign(message)
    seed = opened._signing.copy()
    try:
        seed_in_blob = bytes(seed) in blob
    finally:
        wipe_buffer(seed)
    info: dict[str, object] = {
        "blob": blob,
        "signing_public": opened.signing_public,
        "exchange_public": opened.exchange_public,
        "signature": signature,
        "message": message,
        "seed_in_blob": seed_in_blob,
    }
    opened.close()
    return info


def test_round_trip_and_password_buffer_is_zero(created: dict[str, object]) -> None:
    password = bytearray(PASSWORD)
    opened = Keybag.unlock(password, created["blob"])  # type: ignore[arg-type]
    try:
        assert password == bytearray(len(PASSWORD))
        assert isinstance(opened, UnlockedKeybag)
        verify(
            created["signing_public"],  # type: ignore[arg-type]
            created["signature"],  # type: ignore[arg-type]
            created["message"],  # type: ignore[arg-type]
        )
        file_key = b"file-key-file-key-file-key-file"
        box = seal(created["exchange_public"], file_key)  # type: ignore[arg-type]
        assert opened.open_sealed(box) == file_key
        assert "UnlockedKeybag" in repr(opened)
        assert file_key.decode() not in repr(opened)
    finally:
        opened.close()


def test_device_seed_is_not_stored_in_the_clear(created: dict[str, object]) -> None:
    assert created["seed_in_blob"] is False
    assert len(created["blob"]) == KEYBAG_LEN  # type: ignore[arg-type]


def test_wrong_password_is_a_clear_refusal(created: dict[str, object]) -> None:
    bad = bytearray(b"not-the-password")
    with pytest.raises(PasswordError, match="^wrong password$") as caught:
        Keybag.unlock(bad, created["blob"])  # type: ignore[arg-type]
    assert bad == bytearray(len(bad))
    assert "not-the-password" not in str(caught.value)
    assert "correct horse" not in str(caught.value)


def test_flipped_keybag_byte_is_refused(created: dict[str, object]) -> None:
    blob = bytearray(created["blob"])  # type: ignore[arg-type]
    blob[-1] ^= 0x01
    password = bytearray(PASSWORD)
    with pytest.raises(PasswordError, match="^wrong password$"):
        Keybag.unlock(password, bytes(blob))
    assert password == bytearray(len(PASSWORD))


def test_rewrap_changes_the_password_only(created: dict[str, object]) -> None:
    old = bytearray(PASSWORD)
    new = bytearray(b"a-different-password")
    rewritten = Keybag.rewrap(created["blob"], old, new)  # type: ignore[arg-type]
    assert old == bytearray(len(PASSWORD))
    assert new == bytearray(len(b"a-different-password"))
    assert rewritten != created["blob"]

    opened = Keybag.unlock(bytearray(b"a-different-password"), rewritten)
    try:
        assert opened.signing_public == created["signing_public"]
        assert opened.exchange_public == created["exchange_public"]
        verify(
            opened.signing_public,
            created["signature"],  # type: ignore[arg-type]
            created["message"],  # type: ignore[arg-type]
        )
    finally:
        opened.close()

    stale = bytearray(PASSWORD)
    with pytest.raises(PasswordError, match="^wrong password$"):
        Keybag.unlock(stale, rewritten)
    assert stale == bytearray(len(PASSWORD))


def test_closed_keybag_cannot_sign(created: dict[str, object]) -> None:
    opened = Keybag.unlock(bytearray(PASSWORD), created["blob"])  # type: ignore[arg-type]
    opened.close()
    with pytest.raises(CryptoError, match="closed"):
        opened.sign(b"more")


def test_hostile_parameters_are_refused_before_argon2() -> None:
    salt = bytes(16)
    header = b"PBK1" + bytes([1]) + salt + struct.pack(">III", 2, 0xFFFFFFFF, 1)
    assert len(header) == HEADER_LEN
    blob = header + bytes(KEYBAG_LEN - HEADER_LEN)
    password = bytearray(b"password")
    started = time.monotonic()
    with pytest.raises(FormatError, match="unsupported key derivation parameters"):
        Keybag.unlock(password, blob)
    assert time.monotonic() - started < 2
    assert password == bytearray(len(password))


def test_truncated_keybag_is_refused() -> None:
    with pytest.raises(FormatError, match="not a pebble keybag"):
        Keybag.unlock(bytearray(b"password"), b"nope")
    with pytest.raises(FormatError, match="truncated"):
        Keybag.unlock(bytearray(b"password"), b"PBK1" + b"\x00" * 8)


def test_argon2id_output_matches_the_library_and_can_be_wiped() -> None:
    salt = bytes(range(16))
    derived = _argon2(b"example-password", salt)
    expected = hash_secret_raw(
        b"example-password",
        salt,
        TIME_COST,
        MEMORY_KIB,
        PARALLELISM,
        32,
        Type.ID,
    )
    assert bytes(derived) == expected
    assert bytes(derived) != b"\x00" * 32
    wipe_buffer(derived)
    assert derived == bytearray(32)


def test_password_must_be_a_bytearray() -> None:
    with pytest.raises(TypeError, match="bytearray"):
        Keybag.create("not-a-buffer")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="empty"):
        Keybag.create(bytearray())
