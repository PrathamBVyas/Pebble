"""XChaCha20-Poly1305 for file bytes and listing bytes.

PyCA ships ChaCha20-Poly1305 with a 12-byte nonce. XChaCha20-Poly1305 is
that AEAD with a 24-byte nonce, derived the way draft-irtf-cfrg-xchacha
specifies: HChaCha20 turns the key and the first 16 nonce bytes into a
subkey, then ChaCha20-Poly1305 runs with a nonce of four zero bytes plus
the last 8 nonce bytes. The subkey is wiped before the function returns.

Wire format: the 24-byte nonce, then the ciphertext and its 16-byte tag.
The tag covers the associated data. A chunk sealed for one object id does
not open under another id, so a copied ciphertext cannot be pasted onto a
different object.
"""

from __future__ import annotations

import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from pebble.errors import AuthenticationError
from pebble.secret import wipe_buffer

NONCE_LEN = 24
TAG_LEN = 16
KEY_LEN = 32
_SIGMA = b"expand 32-byte k"


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Seal plaintext. Returns nonce || ciphertext || tag."""
    key_bytes = _key(key)
    body = _message(plaintext, "plaintext")
    associated = _message(aad, "associated data")
    if len(associated) == 0:
        raise ValueError("associated data is required")
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + _seal(key_bytes, nonce, body, associated)


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Open a blob from encrypt. A bad tag raises AuthenticationError."""
    key_bytes = _key(key)
    data = _message(blob, "ciphertext")
    associated = _message(aad, "associated data")
    if len(associated) == 0:
        raise ValueError("associated data is required")
    if len(data) < NONCE_LEN + TAG_LEN:
        raise AuthenticationError()
    nonce = data[:NONCE_LEN]
    ciphertext = data[NONCE_LEN:]
    try:
        return _open(key_bytes, nonce, ciphertext, associated)
    except InvalidTag:
        raise AuthenticationError() from None


def _seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    subkey = _hchacha20(key, nonce[:16])
    try:
        ietf_nonce = b"\x00\x00\x00\x00" + nonce[16:]
        return ChaCha20Poly1305(bytes(subkey)).encrypt(ietf_nonce, plaintext, aad)
    finally:
        wipe_buffer(subkey)


def _open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    subkey = _hchacha20(key, nonce[:16])
    try:
        ietf_nonce = b"\x00\x00\x00\x00" + nonce[16:]
        return ChaCha20Poly1305(bytes(subkey)).decrypt(ietf_nonce, ciphertext, aad)
    finally:
        wipe_buffer(subkey)


def _hchacha20(key: bytes, nonce: bytes) -> bytearray:
    """HChaCha20 subkey. nonce is 16 bytes. The working state is cleared."""
    if len(key) != KEY_LEN or len(nonce) != 16:
        raise ValueError("HChaCha20 expects a 32-byte key and a 16-byte nonce")
    state = list(struct.unpack("<4I", _SIGMA))
    state.extend(struct.unpack("<8I", key))
    state.extend(struct.unpack("<4I", nonce))
    try:
        for _ in range(10):
            _quarter(state, 0, 4, 8, 12)
            _quarter(state, 1, 5, 9, 13)
            _quarter(state, 2, 6, 10, 14)
            _quarter(state, 3, 7, 11, 15)
            _quarter(state, 0, 5, 10, 15)
            _quarter(state, 1, 6, 11, 12)
            _quarter(state, 2, 7, 8, 13)
            _quarter(state, 3, 4, 9, 14)
        return bytearray(
            struct.pack(
                "<8I",
                state[0],
                state[1],
                state[2],
                state[3],
                state[12],
                state[13],
                state[14],
                state[15],
            )
        )
    finally:
        for i in range(len(state)):
            state[i] = 0


def _quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl(state[b], 7)


def _rotl(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def _key(key: bytes) -> bytes:
    if isinstance(key, str) or not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    return bytes(key)


def _message(value: bytes, name: str) -> bytes:
    if isinstance(value, str) or not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    return bytes(value)
