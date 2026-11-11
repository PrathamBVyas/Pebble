"""The witness log only grows, and a bad signature is not a view."""

from pebble.errors import AuthenticationError, FormatError
from pebble.sign import generate_seed, public_key, sign
from pebble.witness import append_view, read_views


def _signer(seed: bytes):
    def sign_note(message: bytes) -> bytes:
        return sign(seed, message)

    return sign_note


def test_notes_round_trip_and_only_grow(tmp_path):
    log = tmp_path / "log"
    seed = generate_seed()
    author = public_key(seed)
    first = "ab" * 32
    second = "cd" * 32
    append_view(log, first, author, _signer(seed))
    prefix = log.read_bytes()
    append_view(log, second, author, _signer(seed))
    assert log.read_bytes().startswith(prefix)
    assert read_views(log, required=True) == [first, second]


def test_missing_log_is_refused_unless_allowed(tmp_path):
    log = tmp_path / "missing"
    try:
        read_views(log, required=True)
    except FormatError as exc:
        assert "missing" in str(exc)
    else:
        raise AssertionError("missing log was accepted")
    assert read_views(log, required=False) == []


def test_torn_tail_is_ignored_and_a_bad_signature_is_not(tmp_path):
    log = tmp_path / "log"
    seed = generate_seed()
    author = public_key(seed)
    head = "11" * 32
    append_view(log, head, author, _signer(seed))
    intact = log.read_bytes()
    log.write_bytes(intact + b"torn")
    assert read_views(log, required=True) == [head]
    flipped = bytearray(intact)
    flipped[-1] ^= 0x01
    log.write_bytes(flipped)
    try:
        read_views(log, required=True)
    except AuthenticationError as exc:
        assert str(exc) == "authentication failed"
    else:
        raise AssertionError("bad signature was accepted")
