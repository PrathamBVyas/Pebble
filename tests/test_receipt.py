"""A receipt checks two commits and needs no password."""

import pytest

from pebble.commit import create_commit
from pebble.errors import FormatError
from pebble.receipt import verify_receipt, write_receipt
from pebble.sign import generate_seed
from pebble.store import Kind, Store


def _commit(store: Store, parents: tuple[str, ...], seed: bytes, label: bytes) -> tuple[str, bytes]:
    listing = store.put(label, kind=Kind.META)
    blob = create_commit(parents=parents, listing=listing, seed=seed)
    object_id = store.put(blob, kind=Kind.META)
    return object_id, blob


def test_sibling_receipt_verifies_and_a_line_does_not(tmp_path):
    store = Store(tmp_path / "objects")
    seed = generate_seed()
    root, root_blob = _commit(store, (), seed, b"root")
    left, left_blob = _commit(store, (root,), seed, b"left")
    right, _right_blob = _commit(store, (root,), seed, b"right")
    path = tmp_path / "receipt"
    write_receipt(path, left_blob, store.get(right, kind=Kind.META))
    found = verify_receipt(path)
    assert set(found) == {left, right}
    with pytest.raises(FormatError, match="not a fork"):
        write_receipt(tmp_path / "line", root_blob, left_blob)
