"""Ed25519 signatures are detached, and a flipped byte fails closed."""

import pytest

from pebble.errors import AuthenticationError
from pebble.sign import SIGNATURE_LEN, generate_seed, public_key, sign, verify


def test_round_trip() -> None:
    seed = generate_seed()
    message = b"parent hash and listing hash"
    signature = sign(seed, message)
    assert len(signature) == SIGNATURE_LEN
    assert message not in signature
    verify(public_key(seed), signature, message)


def test_flipped_signature_byte_is_refused() -> None:
    seed = generate_seed()
    message = b"commit"
    signature = bytearray(sign(seed, message))
    signature[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        verify(public_key(seed), bytes(signature), message)


def test_wrong_message_is_refused() -> None:
    seed = generate_seed()
    signature = sign(seed, b"one")
    with pytest.raises(AuthenticationError):
        verify(public_key(seed), signature, b"two")


def test_truncated_signature_is_refused() -> None:
    seed = generate_seed()
    with pytest.raises(AuthenticationError):
        verify(public_key(seed), b"\x00" * 8, b"commit")
