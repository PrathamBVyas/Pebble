"""Detached Ed25519 signatures for commits and grants.

A signature is 64 bytes. Verification checks that signature against the exact
message bytes and one public key.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pebble.errors import AuthenticationError
from pebble.secret import wipe_buffer

SEED_LEN = 32
PUBLIC_LEN = 32
SIGNATURE_LEN = 64


def generate_seed() -> bytes:
    return secrets.token_bytes(SEED_LEN)


def public_key(seed: bytes) -> bytes:
    material = _seed(seed)
    try:
        private = Ed25519PrivateKey.from_private_bytes(bytes(material))
        return _raw_public(private.public_key())
    finally:
        wipe_buffer(material)


def sign(seed: bytes, message: bytes) -> bytes:
    """Return a detached 64-byte signature."""
    material = _seed(seed)
    try:
        body = _bytes(message, "message")
        private = Ed25519PrivateKey.from_private_bytes(bytes(material))
        return private.sign(body)
    finally:
        wipe_buffer(material)


def verify(public: bytes, signature: bytes, message: bytes) -> None:
    """Raise AuthenticationError unless signature is valid for message."""
    raw_public = _bytes(public, "public key")
    raw_signature = _bytes(signature, "signature")
    body = _bytes(message, "message")
    if len(raw_public) != PUBLIC_LEN or len(raw_signature) != SIGNATURE_LEN:
        raise AuthenticationError()
    try:
        key = Ed25519PublicKey.from_public_bytes(raw_public)
        key.verify(raw_signature, body)
    except (InvalidSignature, ValueError):
        raise AuthenticationError() from None


def _seed(seed: bytes) -> bytearray:
    if isinstance(seed, str) or not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) != SEED_LEN:
        raise ValueError("ed25519 seed must be 32 bytes")
    return bytearray(seed)


def _bytes(value: bytes, name: str) -> bytes:
    if isinstance(value, str) or not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    return bytes(value)


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
