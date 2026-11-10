"""Secret buffers wipe, and they do not reveal themselves in text."""

import pickle

import pytest

from pebble.errors import CryptoError
from pebble.secret import Secret, _zero_map, wipe_buffer


def test_wipe_buffer_zeroes_a_password() -> None:
    buf = bytearray(b"correct horse battery staple")
    wipe_buffer(buf)
    assert buf == bytearray(len(buf))


def test_secret_bytes_are_zero_before_the_page_is_released() -> None:
    payload = b"super-secret-key-material!!"
    secret = Secret(payload)
    assert secret._mm is not None
    assert bytes(secret._mm[: len(payload)]) == payload
    _zero_map(secret._mm, len(payload))
    assert bytes(secret._mm[: len(payload)]) == b"\x00" * len(payload)
    secret.wipe()
    assert secret.wiped
    with pytest.raises(CryptoError, match="wiped"):
        secret.copy()


def test_repr_hides_secret_bytes() -> None:
    payload = b"hunter2-hunter2-hunter2-hunter2"
    secret = Secret(payload)
    assert b"hunter2" not in repr(secret).encode()
    assert b"hunter2" not in str(secret).encode()
    secret.wipe()
    secret.wipe()


def test_secret_cannot_be_pickled() -> None:
    secret = Secret(b"do-not-serialize-this-secret!!")
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    secret.wipe()


def test_empty_secret_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        Secret(b"")
