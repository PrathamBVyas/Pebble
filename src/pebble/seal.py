"""An X25519 sealed box for one file key or one listing key.

The sender generates an ephemeral X25519 key, runs HKDF-SHA256 over the
shared secret, and encrypts with XChaCha20-Poly1305. The ephemeral secret,
the shared secret, and the derived key are wiped before the function returns.

Wire format:
    ephemeral public key (32) || nonce (24) || ciphertext || tag (16)

The tag covers the label and both public keys. A box opened with any other
private key fails the tag.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pebble.aead import _open, _seal
from pebble.errors import AuthenticationError
from pebble.secret import wipe_buffer

LABEL = b"pebble-seal-v1"
KEY_LEN = 32
NONCE_LEN = 24
TAG_LEN = 16
PUBLIC_LEN = 32


def generate_private() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def public_key(private: bytes) -> bytes:
    material = _private(private)
    try:
        key = X25519PrivateKey.from_private_bytes(bytes(material))
        return _raw_public(key.public_key())
    finally:
        wipe_buffer(material)


def seal(recipient_public: bytes, plaintext: bytes) -> bytes:
    """Wrap plaintext to one X25519 public key."""
    recipient = _public(recipient_public)
    body = _bytes(plaintext, "plaintext")
    ephemeral = bytearray(secrets.token_bytes(KEY_LEN))
    shared = bytearray()
    try:
        private = X25519PrivateKey.from_private_bytes(bytes(ephemeral))
        ephemeral_public = _raw_public(private.public_key())
        shared = bytearray(private.exchange(_load_public(recipient)))
        return _encrypt(shared, ephemeral_public, recipient, body)
    finally:
        wipe_buffer(shared)
        wipe_buffer(ephemeral)


def open_seal(recipient_private: bytes, blob: bytes) -> bytes:
    """Open a box addressed to the matching private key."""
    material = _private(recipient_private)
    try:
        data = _bytes(blob, "sealed box")
        if len(data) < PUBLIC_LEN + NONCE_LEN + TAG_LEN:
            raise AuthenticationError()
        ephemeral_public = data[:PUBLIC_LEN]
        nonce = data[PUBLIC_LEN : PUBLIC_LEN + NONCE_LEN]
        ciphertext = data[PUBLIC_LEN + NONCE_LEN :]
        shared = bytearray()
        key = bytearray()
        try:
            try:
                private = X25519PrivateKey.from_private_bytes(bytes(material))
                recipient_public = _raw_public(private.public_key())
                shared = bytearray(private.exchange(_load_public(ephemeral_public)))
            except ValueError:
                raise AuthenticationError() from None
            try:
                key = _derive(shared, ephemeral_public, recipient_public)
                return _open(
                    bytes(key),
                    nonce,
                    ciphertext,
                    _aad(ephemeral_public, recipient_public),
                )
            except InvalidTag:
                raise AuthenticationError() from None
        finally:
            wipe_buffer(key)
            wipe_buffer(shared)
    finally:
        wipe_buffer(material)


def _encrypt(
    shared: bytearray,
    ephemeral_public: bytes,
    recipient: bytes,
    body: bytes,
) -> bytes:
    key = _derive(shared, ephemeral_public, recipient)
    try:
        nonce = secrets.token_bytes(NONCE_LEN)
        ciphertext = _seal(bytes(key), nonce, body, _aad(ephemeral_public, recipient))
        return ephemeral_public + nonce + ciphertext
    finally:
        wipe_buffer(key)


def _derive(shared: bytes, ephemeral_public: bytes, recipient_public: bytes) -> bytearray:
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=ephemeral_public + recipient_public,
        info=LABEL,
    ).derive(bytes(shared))
    return bytearray(raw)


def _aad(ephemeral_public: bytes, recipient_public: bytes) -> bytes:
    return LABEL + ephemeral_public + recipient_public


def _load_public(public: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(public)


def _private(private: bytes) -> bytearray:
    if isinstance(private, str) or not isinstance(private, (bytes, bytearray)):
        raise TypeError("x25519 private key must be bytes")
    if len(private) != KEY_LEN:
        raise ValueError("x25519 private key must be 32 bytes")
    return bytearray(private)


def _public(public: bytes) -> bytes:
    raw = _bytes(public, "x25519 public key")
    if len(raw) != PUBLIC_LEN:
        raise ValueError("x25519 public key must be 32 bytes")
    return raw


def _bytes(value: bytes, name: str) -> bytes:
    if isinstance(value, str) or not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    return bytes(value)


def _raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
