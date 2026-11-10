"""An X25519 sealed box round-trips one key and refuses a flipped byte."""

import secrets

import pytest

from pebble.errors import AuthenticationError
from pebble.seal import generate_private, open_seal, public_key, seal


def test_round_trip() -> None:
    private = generate_private()
    file_key = secrets.token_bytes(32)
    box = seal(public_key(private), file_key)
    assert file_key not in box
    assert open_seal(private, box) == file_key


def test_flipped_byte_is_refused() -> None:
    private = generate_private()
    box = bytearray(seal(public_key(private), b"listing-key-material-goes-here!"))
    box[-1] ^= 0x01
    with pytest.raises(AuthenticationError):
        open_seal(private, bytes(box))


def test_wrong_recipient_is_refused() -> None:
    owner = generate_private()
    stranger = generate_private()
    box = seal(public_key(owner), b"file-key-file-key-file-key-file")
    with pytest.raises(AuthenticationError):
        open_seal(stranger, box)


def test_truncated_box_is_refused() -> None:
    private = generate_private()
    with pytest.raises(AuthenticationError):
        open_seal(private, b"\x00" * 8)
