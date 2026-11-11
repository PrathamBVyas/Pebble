"""Failures from the lock primitives.

Messages name the failure and never include a password, a key, or plaintext.
"""

from __future__ import annotations


class CryptoError(Exception):
    """A cryptographic operation failed or was used after its secrets were wiped."""


class AuthenticationError(CryptoError):
    """A ciphertext tag or a signature check failed."""

    def __init__(self) -> None:
        super().__init__("authentication failed")


class PasswordError(CryptoError):
    """The keybag did not open.

    A wrong password and a flipped keybag byte both fail the authentication
    tag. Callers get one refusal either way.
    """

    def __init__(self) -> None:
        super().__init__("wrong password")


class FormatError(CryptoError):
    """The bytes are not a well-formed pebble cryptographic object."""


class MergeConflict(Exception):
    """Both sides of a merge changed the same path."""

    def __init__(self) -> None:
        super().__init__("both sides changed the same file")
