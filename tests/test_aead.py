"""XChaCha20-Poly1305 round-trips, and a flipped byte or a swapped id fails."""

import secrets

import pytest

from pebble.aead import KEY_LEN, NONCE_LEN, TAG_LEN, _hchacha20, _open, _seal, decrypt, encrypt
from pebble.errors import AuthenticationError


def test_round_trip() -> None:
    key = secrets.token_bytes(KEY_LEN)
    plaintext = b"the file bytes"
    blob = encrypt(key, plaintext, b"object-id")
    assert decrypt(key, blob, b"object-id") == plaintext
    assert plaintext not in blob
    assert len(blob) == len(plaintext) + NONCE_LEN + TAG_LEN


def test_empty_plaintext_round_trips() -> None:
    key = secrets.token_bytes(KEY_LEN)
    blob = encrypt(key, b"", b"object-id")
    assert decrypt(key, blob, b"object-id") == b""


def test_each_encryption_uses_a_fresh_nonce() -> None:
    key = secrets.token_bytes(KEY_LEN)
    first = encrypt(key, b"same", b"object-id")
    second = encrypt(key, b"same", b"object-id")
    assert first != second


def test_flipped_ciphertext_byte_is_refused() -> None:
    key = secrets.token_bytes(KEY_LEN)
    plaintext = b"very-unique-plaintext"
    blob = bytearray(encrypt(key, plaintext, b"object-id"))
    blob[-1] ^= 0x01
    with pytest.raises(AuthenticationError, match="^authentication failed$") as caught:
        decrypt(key, bytes(blob), b"object-id")
    assert plaintext.decode() not in str(caught.value)


def test_tag_is_bound_to_the_object_id() -> None:
    key = secrets.token_bytes(KEY_LEN)
    blob = encrypt(key, b"chunk", b"object-a")
    with pytest.raises(AuthenticationError):
        decrypt(key, blob, b"object-b")


def test_wrong_key_is_refused() -> None:
    key = secrets.token_bytes(KEY_LEN)
    blob = encrypt(key, b"chunk", b"object-id")
    with pytest.raises(AuthenticationError):
        decrypt(secrets.token_bytes(KEY_LEN), blob, b"object-id")


def test_truncated_ciphertext_is_refused() -> None:
    key = secrets.token_bytes(KEY_LEN)
    with pytest.raises(AuthenticationError):
        decrypt(key, b"\x00" * 8, b"object-id")


def test_associated_data_is_required() -> None:
    key = secrets.token_bytes(KEY_LEN)
    with pytest.raises(ValueError, match="associated data"):
        encrypt(key, b"chunk", b"")


def test_key_must_be_32_bytes() -> None:
    with pytest.raises(ValueError, match="32"):
        encrypt(b"short", b"chunk", b"object-id")


def test_hchacha20_matches_the_xchacha_draft() -> None:
    # draft-irtf-cfrg-xchacha-03, section 2.2.1.
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    expected = bytes.fromhex(
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    )
    assert bytes(_hchacha20(key, nonce)) == expected


def test_xchacha20poly1305_matches_the_xchacha_draft() -> None:
    # draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"
    )
    expected = bytes.fromhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"
        "c0875924c1c7987947deafd8780acf49"
    )
    sealed = _seal(key, nonce, plaintext, aad)
    assert sealed == expected
    assert _open(key, nonce, sealed, aad) == plaintext
