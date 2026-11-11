"""Three signed saves walk back. A flipped signature byte does not."""

from pathlib import Path

import pytest

from pebble.commit import create_commit, lineage, load_commit, verify_commit
from pebble.errors import AuthenticationError, FormatError
from pebble.sign import generate_seed, public_key
from pebble.store import Kind, Store

LISTING_A = "11" * 32
LISTING_B = "22" * 32
LISTING_C = "33" * 32


def test_three_saves_walk_back(tmp_path: Path) -> None:
    store = Store(tmp_path)
    seed = generate_seed()
    first = create_commit(parents=(), listing=LISTING_A, seed=seed)
    first_id = store.put(first, kind=Kind.META)
    second = create_commit(parents=(first_id,), listing=LISTING_B, seed=seed)
    second_id = store.put(second, kind=Kind.META)
    third = create_commit(parents=(second_id,), listing=LISTING_C, seed=seed)
    third_id = store.put(third, kind=Kind.META)

    chain = lineage(store, third_id)
    assert [commit.listing.hex() for commit in chain] == [LISTING_C, LISTING_B, LISTING_A]
    assert chain[0].parents == (bytes.fromhex(second_id),)
    assert chain[1].parents == (bytes.fromhex(first_id),)
    assert chain[2].parents == ()
    assert chain[0].author == public_key(seed)
    # The commit is readable without a vault password: the magic is on disk.
    assert store.get(first_id, kind=Kind.META).startswith(b"PCMT")


def test_flipped_signature_byte_is_refused(tmp_path: Path) -> None:
    store = Store(tmp_path)
    seed = generate_seed()
    blob = bytearray(create_commit(parents=(), listing=LISTING_A, seed=seed))
    blob[-1] ^= 0x01
    with pytest.raises(AuthenticationError, match="^authentication failed$"):
        verify_commit(bytes(blob))
    bad_id = store.put(bytes(blob), kind=Kind.META)
    with pytest.raises(AuthenticationError):
        load_commit(store, bad_id)


def test_two_parents_verify_and_three_are_refused() -> None:
    seed = generate_seed()
    blob = create_commit(parents=("ab" * 32, "cd" * 32), listing=LISTING_A, seed=seed)
    commit = verify_commit(blob)
    assert len(commit.parents) == 2
    with pytest.raises(FormatError, match="too many parents"):
        create_commit(
            parents=("ab" * 32, "cd" * 32, "ef" * 32),
            listing=LISTING_A,
            seed=seed,
        )


def test_changed_parent_fails_the_signature() -> None:
    seed = generate_seed()
    blob = bytearray(
        create_commit(parents=("ab" * 32,), listing=LISTING_A, seed=seed)
    )
    blob[6] ^= 0x01
    with pytest.raises(AuthenticationError):
        verify_commit(bytes(blob))
