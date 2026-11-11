"""Table tests for update, rewind, and split, plus a clean merge."""

import pytest

from pebble.commit import verify_commit
from pebble.errors import MergeConflict
from pebble.history import classify, merge_commit
from pebble.sign import generate_seed, public_key
from pebble.tree import Dir

Graph = tuple[tuple[str, tuple[str, ...]], ...]


@pytest.mark.parametrize(
    ("accepted", "witnessed", "tips", "links", "kind", "head"),
    [
        ({"a"}, set(), {"b"}, (("a", ()), ("b", ("a",))), "update", "b"),
        (
            {"a"},
            set(),
            {"c"},
            (("a", ()), ("b", ("a",)), ("c", ("b",))),
            "update",
            "c",
        ),
        ({"a"}, set(), {"a"}, (("a", ()),), "update", "a"),
        ({"b"}, set(), {"a"}, (("a", ()), ("b", ("a",))), "rewind", "b"),
        (
            {"c"},
            set(),
            {"a"},
            (("a", ()), ("b", ("a",)), ("c", ("b",))),
            "rewind",
            "c",
        ),
        (
            {"a"},
            set(),
            {"b", "c"},
            (("a", ()), ("b", ("a",)), ("c", ("a",))),
            "split",
            "a",
        ),
        (
            {"a"},
            {"c"},
            {"b"},
            (("a", ()), ("b", ("a",)), ("c", ("a",))),
            "split",
            "a",
        ),
        ({"a"}, {"b"}, {"a"}, (("a", ()), ("b", ("a",))), "rewind", "b"),
        ({"a"}, set(), {"c"}, (("c", ("b",)),), "split", "a"),
        ({"a"}, set(), {"a", "b"}, (("a", ()), ("b", ("a",))), "update", "b"),
        ({"a"}, {"a"}, {"b"}, (("a", ()), ("b", ("a",))), "update", "b"),
    ],
)
def test_classify_table(
    accepted: set[str],
    witnessed: set[str],
    tips: set[str],
    links: Graph,
    kind: str,
    head: str,
) -> None:
    verdict = classify(
        accepted=accepted,
        witnessed=witnessed,
        tips=tips,
        parents=dict(links),
    )
    assert verdict.kind == kind
    assert verdict.head == head


def test_a_merge_commit_can_fast_forward_through_either_parent() -> None:
    links = {
        "a": (),
        "left": ("a",),
        "right": ("a",),
        "merged": ("left", "right"),
    }
    verdict = classify(accepted={"a"}, witnessed=set(), tips={"merged"}, parents=links)
    assert verdict.kind == "update"
    assert verdict.head == "merged"

    # The other parent of the merge is not loaded. The loaded parent still
    # reaches the accepted head, so this stays an update.
    partial = {"a": (), "left": ("a",), "merged": ("left", "missing")}
    verdict = classify(accepted={"a"}, witnessed=set(), tips={"merged"}, parents=partial)
    assert verdict.kind == "update"


def test_one_side_can_delete_an_unchanged_file() -> None:
    base = Dir()
    base.files["keep"] = b"stay"
    base.files["gone"] = b"remove"
    left = Dir()
    left.files["keep"] = b"stay"
    right = Dir()
    right.files["keep"] = b"stay"
    right.files["gone"] = b"remove"
    merged, _blob = merge_commit(
        base=base,
        left=left,
        right=right,
        left_id="aa" * 32,
        right_id="bb" * 32,
        listing="cc" * 32,
        seed=generate_seed(),
    )
    assert merged.files == {"keep": b"stay"}


def test_clean_merge_builds_a_two_parent_commit() -> None:
    base = Dir()
    left = Dir()
    left.files["a"] = b"from-left"
    right = Dir()
    right.files["b"] = b"from-right"
    seed = generate_seed()
    merged, blob = merge_commit(
        base=base,
        left=left,
        right=right,
        left_id="aa" * 32,
        right_id="bb" * 32,
        listing="cc" * 32,
        seed=seed,
    )
    assert merged.files == {"a": b"from-left", "b": b"from-right"}
    commit = verify_commit(blob)
    assert commit.parents == (bytes.fromhex("aa" * 32), bytes.fromhex("bb" * 32))
    assert commit.listing == bytes.fromhex("cc" * 32)
    assert commit.author == public_key(seed)


def test_edits_to_different_files_merge() -> None:
    base = Dir()
    base.files["a"] = b"old-a"
    base.files["b"] = b"old-b"
    left = Dir()
    left.files["a"] = b"new-a"
    left.files["b"] = b"old-b"
    right = Dir()
    right.files["a"] = b"old-a"
    right.files["b"] = b"new-b"
    merged, _blob = merge_commit(
        base=base,
        left=left,
        right=right,
        left_id="aa" * 32,
        right_id="bb" * 32,
        listing="cc" * 32,
        seed=generate_seed(),
    )
    assert merged.files == {"a": b"new-a", "b": b"new-b"}


def test_the_same_edit_on_both_sides_is_kept() -> None:
    base = Dir()
    base.files["a"] = b"old"
    left = Dir()
    left.files["a"] = b"same"
    right = Dir()
    right.files["a"] = b"same"
    merged, _blob = merge_commit(
        base=base,
        left=left,
        right=right,
        left_id="aa" * 32,
        right_id="bb" * 32,
        listing="cc" * 32,
        seed=generate_seed(),
    )
    assert merged.files == {"a": b"same"}


def test_both_sides_changing_one_file_is_refused() -> None:
    base = Dir()
    base.files["a"] = b"old"
    left = Dir()
    left.files["a"] = b"left"
    right = Dir()
    right.files["a"] = b"right"
    with pytest.raises(MergeConflict, match="^both sides changed the same file$"):
        merge_commit(
            base=base,
            left=left,
            right=right,
            left_id="aa" * 32,
            right_id="bb" * 32,
            listing="cc" * 32,
            seed=generate_seed(),
        )


def test_delete_against_an_edit_is_refused() -> None:
    base = Dir()
    base.files["a"] = b"old"
    left = Dir()
    right = Dir()
    right.files["a"] = b"edited"
    with pytest.raises(MergeConflict):
        merge_commit(
            base=base,
            left=left,
            right=right,
            left_id="aa" * 32,
            right_id="bb" * 32,
            listing="cc" * 32,
            seed=generate_seed(),
        )


def test_nested_edits_on_different_files_merge() -> None:
    base = Dir()
    base.dirs["sub"] = Dir()
    base.dirs["sub"].files["a"] = b"old-a"
    base.dirs["sub"].files["b"] = b"old-b"
    left = Dir()
    left.dirs["sub"] = Dir()
    left.dirs["sub"].files["a"] = b"new-a"
    left.dirs["sub"].files["b"] = b"old-b"
    right = Dir()
    right.dirs["sub"] = Dir()
    right.dirs["sub"].files["a"] = b"old-a"
    right.dirs["sub"].files["b"] = b"new-b"
    merged, _blob = merge_commit(
        base=base,
        left=left,
        right=right,
        left_id="aa" * 32,
        right_id="bb" * 32,
        listing="cc" * 32,
        seed=generate_seed(),
    )
    assert merged.dirs["sub"].files == {"a": b"new-a", "b": b"new-b"}
