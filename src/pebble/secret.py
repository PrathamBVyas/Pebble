"""Secret bytes that can be wiped.

A password or a derived key is copied into its own memory mapping. The page
is locked with mlock when the kernel allows it, and the mapping is overwritten
with zeros on close. Best effort: a refused mlock does not stop the wipe.
"""

from __future__ import annotations

import ctypes
import mmap

from pebble.errors import CryptoError

_PAGE = 4096
_MAX_SECRET = 1024 * 1024
# Linux include/uapi/asm-generic/mman-common.h
_MADV_DONTDUMP = 16


def wipe_buffer(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros."""
    if not isinstance(buf, bytearray):
        raise TypeError("wipe_buffer requires a bytearray")
    n = len(buf)
    if n == 0:
        return
    view = (ctypes.c_char * n).from_buffer(buf)
    ctypes.memset(view, 0, n)


def _libc() -> ctypes.CDLL | None:
    try:
        return ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None


def _map_address(mapping: mmap.mmap) -> int:
    view = (ctypes.c_char * 1).from_buffer(mapping)
    return ctypes.addressof(view)


def _zero_map(mapping: mmap.mmap, n: int) -> None:
    view = (ctypes.c_char * n).from_buffer(mapping)
    ctypes.memset(view, 0, n)


def _lock_pages(address: int, size: int) -> bool:
    libc = _libc()
    if libc is None or size <= 0:
        return False
    try:
        mlock = libc.mlock
        mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        mlock.restype = ctypes.c_int
        locked = mlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
        madvise = getattr(libc, "madvise", None)
        if madvise is not None:
            madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            madvise.restype = ctypes.c_int
            madvise(ctypes.c_void_p(address), ctypes.c_size_t(size), _MADV_DONTDUMP)
        return locked
    except (AttributeError, OSError):
        return False


def _unlock_pages(address: int, size: int) -> None:
    libc = _libc()
    if libc is None or size <= 0:
        return
    try:
        munlock = libc.munlock
        munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        munlock.restype = ctypes.c_int
        munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
    except (AttributeError, OSError):
        return


class Secret:
    """One secret in a private mapping. Close overwrites it."""

    def __init__(self, data: bytes) -> None:
        if isinstance(data, str) or not isinstance(data, (bytes, bytearray)):
            raise TypeError("secret data must be bytes")
        n = len(data)
        if n == 0:
            raise ValueError("secret must not be empty")
        if n > _MAX_SECRET:
            raise ValueError("secret is too large")
        self._n = n
        self._size = (n + _PAGE - 1) & ~(_PAGE - 1)
        self._mm: mmap.mmap | None = mmap.mmap(
            -1, self._size, prot=mmap.PROT_READ | mmap.PROT_WRITE
        )
        self._mm[:n] = bytes(data)
        self._wiped = False
        self._locked = _lock_pages(_map_address(self._mm), self._size)

    def __len__(self) -> int:
        return self._n

    def __repr__(self) -> str:
        state = "wiped" if self._wiped else "live"
        return f"Secret(len={self._n}, {state})"

    def __str__(self) -> str:
        return repr(self)

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            return

    def __getstate__(self) -> None:
        raise TypeError("secrets cannot be pickled")

    @property
    def wiped(self) -> bool:
        return self._wiped

    def copy(self) -> bytearray:
        """Return a fresh bytearray. The caller wipes it."""
        self._check()
        assert self._mm is not None
        return bytearray(self._mm[: self._n])

    def wipe(self) -> None:
        if self._wiped or self._mm is None:
            return
        _zero_map(self._mm, self._n)
        if self._locked:
            _unlock_pages(_map_address(self._mm), self._size)
            self._locked = False
        self._mm.close()
        self._mm = None
        self._wiped = True

    def _check(self) -> None:
        if self._wiped or self._mm is None:
            raise CryptoError("secret has been wiped")
