"""Password keybag for the device signing key.

Argon2id stretches the password into a key. That key seals an Ed25519 seed
and an X25519 seed with XChaCha20-Poly1305. The password buffer the caller
passed in is wiped when this returns, including when the password is wrong.

Nothing here touches the filesystem. The caller keeps the blob.

Blob layout, version 1:
    magic PBK1 (4)
    kdf id 1, Argon2id (1)
    salt (16)
    time, memory KiB, parallelism as big-endian u32 (12)
    XChaCha20-Poly1305 nonce || ciphertext || tag of the identity

The header is the associated data, so a changed salt or a changed cost is a
failed tag. Costs other than the ones this version writes are refused before
Argon2 runs.

Identity layout inside the ciphertext:
    magic PKI1 (4) || ed25519 seed (32) || x25519 private key (32)
"""

from __future__ import annotations

import secrets
import struct

from argon2.low_level import ARGON2_VERSION, Type, ffi, lib

from pebble.aead import TAG_LEN, decrypt, encrypt
from pebble.errors import (
    AuthenticationError,
    CryptoError,
    FormatError,
    PasswordError,
)
from pebble.seal import open_seal
from pebble.seal import public_key as exchange_public
from pebble.secret import Secret, wipe_buffer
from pebble.sign import public_key as signing_public
from pebble.sign import sign

MAGIC = b"PBK1"
PLAIN_MAGIC = b"PKI1"
KDF_ARGON2ID = 1
SALT_LEN = 16
# OWASP minimum for Argon2id: 19 MiB and 2 iterations at parallelism 1.
TIME_COST = 2
MEMORY_KIB = 19_456
PARALLELISM = 1
HEADER_LEN = 4 + 1 + SALT_LEN + 4 + 4 + 4
SEED_LEN = 32
PLAIN_LEN = 4 + SEED_LEN + SEED_LEN
KEYBAG_LEN = HEADER_LEN + 24 + PLAIN_LEN + TAG_LEN


def _require_password(password: bytearray) -> None:
    if not isinstance(password, bytearray):
        raise TypeError("password must be a bytearray so it can be wiped")
    if len(password) == 0:
        raise ValueError("password is empty")


class UnlockedKeybag:
    """Device keys held after the keybag opens. Close wipes them."""

    def __init__(self, signing_seed: bytes, exchange_seed: bytes) -> None:
        self._closed = False
        self._signing = Secret(signing_seed)
        self._exchange = Secret(exchange_seed)
        signing_copy = bytearray()
        exchange_copy = bytearray()
        try:
            signing_copy = self._signing.copy()
            exchange_copy = self._exchange.copy()
            self.signing_public = signing_public(signing_copy)
            self.exchange_public = exchange_public(exchange_copy)
        except Exception:
            self.close()
            raise
        finally:
            wipe_buffer(signing_copy)
            wipe_buffer(exchange_copy)

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"UnlockedKeybag({state})"

    def __str__(self) -> str:
        return repr(self)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            return

    def sign(self, message: bytes) -> bytes:
        seed = self._copy_signing()
        try:
            return sign(seed, message)
        finally:
            wipe_buffer(seed)

    def open_sealed(self, blob: bytes) -> bytes:
        seed = self._copy_exchange()
        try:
            return open_seal(seed, blob)
        finally:
            wipe_buffer(seed)

    def close(self) -> None:
        if self._closed:
            return
        signing = getattr(self, "_signing", None)
        exchange = getattr(self, "_exchange", None)
        if signing is not None:
            signing.wipe()
        if exchange is not None:
            exchange.wipe()
        self._closed = True

    def _copy_signing(self) -> bytearray:
        self._check()
        return self._signing.copy()

    def _copy_exchange(self) -> bytearray:
        self._check()
        return self._exchange.copy()

    def _check(self) -> None:
        if self._closed:
            raise CryptoError("keybag is closed")


class Keybag:
    """Create, open, and rewrap a password keybag. No disk writes."""

    @staticmethod
    def create(password: bytearray) -> tuple[bytes, UnlockedKeybag]:
        """Build a new device identity. Wipes password."""
        _require_password(password)
        secret = bytearray(password)
        signing = bytearray(secrets.token_bytes(SEED_LEN))
        exchange = bytearray(secrets.token_bytes(SEED_LEN))
        try:
            blob = _wrap(secret, signing, exchange)
            opened = UnlockedKeybag(signing, exchange)
            return blob, opened
        finally:
            wipe_buffer(password)
            wipe_buffer(secret)
            wipe_buffer(signing)
            wipe_buffer(exchange)

    @staticmethod
    def unlock(password: bytearray, blob: bytes) -> UnlockedKeybag:
        """Open a keybag. Wipes password. Raises PasswordError on a bad tag."""
        _require_password(password)
        secret = bytearray(password)
        signing = bytearray()
        exchange = bytearray()
        try:
            signing, exchange = _unwrap(secret, blob)
            return UnlockedKeybag(signing, exchange)
        finally:
            wipe_buffer(password)
            wipe_buffer(secret)
            wipe_buffer(signing)
            wipe_buffer(exchange)

    @staticmethod
    def rewrap(blob: bytes, old_password: bytearray, new_password: bytearray) -> bytes:
        """Seal the same device identity under a new password.

        The signing key and the exchange key do not change. Both password
        buffers are wiped.
        """
        _require_password(old_password)
        _require_password(new_password)
        opened: UnlockedKeybag | None = None
        signing = bytearray()
        exchange = bytearray()
        try:
            opened = Keybag.unlock(old_password, blob)
            signing = opened._copy_signing()
            exchange = opened._copy_exchange()
            fresh = bytearray(new_password)
            try:
                return _wrap(fresh, signing, exchange)
            finally:
                wipe_buffer(fresh)
        finally:
            wipe_buffer(old_password)
            wipe_buffer(new_password)
            wipe_buffer(signing)
            wipe_buffer(exchange)
            if opened is not None:
                opened.close()


def _wrap(password: bytes, signing: bytes, exchange: bytes) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    header = _header(salt)
    kek = _argon2(password, salt)
    try:
        plain = PLAIN_MAGIC + bytes(signing) + bytes(exchange)
        return header + encrypt(kek, plain, header)
    finally:
        wipe_buffer(kek)


def _unwrap(password: bytes, blob: bytes) -> tuple[bytearray, bytearray]:
    header = _parse(blob)
    salt = header[5 : 5 + SALT_LEN]
    kek = _argon2(password, salt)
    try:
        try:
            plain = decrypt(bytes(kek), bytes(blob)[HEADER_LEN:], header)
        except AuthenticationError:
            raise PasswordError() from None
    finally:
        wipe_buffer(kek)
    if len(plain) != PLAIN_LEN or plain[:4] != PLAIN_MAGIC:
        raise FormatError("keybag payload is not a device identity")
    return bytearray(plain[4:36]), bytearray(plain[36:68])


def _header(salt: bytes) -> bytes:
    return (
        MAGIC
        + bytes([KDF_ARGON2ID])
        + salt
        + struct.pack(">III", TIME_COST, MEMORY_KIB, PARALLELISM)
    )


def _parse(blob: bytes) -> bytes:
    if isinstance(blob, str) or not isinstance(blob, (bytes, bytearray)):
        raise TypeError("keybag must be bytes")
    data = bytes(blob)
    if len(data) < 4 or data[:4] != MAGIC:
        raise FormatError("not a pebble keybag")
    if len(data) != KEYBAG_LEN:
        if len(data) < KEYBAG_LEN:
            raise FormatError("keybag is truncated")
        raise FormatError("keybag is too large")
    if data[4] != KDF_ARGON2ID:
        raise FormatError("unsupported key derivation")
    time_cost, memory_kib, parallelism = struct.unpack(">III", data[21:33])
    if (time_cost, memory_kib, parallelism) != (TIME_COST, MEMORY_KIB, PARALLELISM):
        raise FormatError("unsupported key derivation parameters")
    return data[:HEADER_LEN]


def _argon2(password: bytes, salt: bytes) -> bytearray:
    """Argon2id into a bytearray. The password copy is wiped before return."""
    secret = bytearray(password)
    out = bytearray(32)
    c_secret = None
    c_out = None
    c_salt = None
    ready = False
    try:
        c_secret = ffi.from_buffer("uint8_t[]", secret)
        c_out = ffi.from_buffer("uint8_t[]", out)
        c_salt = ffi.new("uint8_t[]", bytes(salt))
        rv = lib.argon2_hash(
            TIME_COST,
            MEMORY_KIB,
            PARALLELISM,
            c_secret,
            len(secret),
            c_salt,
            len(salt),
            c_out,
            len(out),
            ffi.NULL,
            0,
            Type.ID.value,
            ARGON2_VERSION,
        )
        if rv != lib.ARGON2_OK:
            raise CryptoError("key derivation failed")
        ready = True
        return out
    finally:
        del c_secret, c_out, c_salt
        wipe_buffer(secret)
        if not ready:
            wipe_buffer(out)

